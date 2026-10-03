import contextlib
import importlib.util
import io
import tempfile
import sys
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "import_helper.py"
spec = importlib.util.spec_from_file_location("lowkey_import_helper", MODULE)
helper = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = helper
spec.loader.exec_module(helper)


class ImportHelperTests(unittest.TestCase):
    def project(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        (root / "src").mkdir()
        (root / "lib" / "demo" / "src").mkdir(parents=True)
        (root / "lib" / "demo" / "lib" / "forge-std" / "src").mkdir(parents=True)
        (root / "foundry.toml").write_text(
            '[profile.default]\nsrc="src"\nlibs=["lib"]\n',
            encoding="utf-8",
        )
        (root / "remappings.txt").write_text(
            "demo/=lib/demo/src/\n"
            "lib/demo/:forge-std/=lib/demo/lib/forge-std/src/\n",
            encoding="utf-8",
        )
        (root / "src" / "A.sol").write_text(
            "pragma solidity ^0.8.20;\ncontract A {}\ninterface IA {}\nlibrary ALib {}\n"
            "struct Data { uint256 x; }\nenum State { A, B }\ntype Amount is uint256;\n"
            "error Bad();\nuint256 constant LIMIT = 1;\n",
            encoding="utf-8",
        )
        (root / "lib" / "demo" / "src" / "Ownable.sol").write_text(
            "pragma solidity ^0.8.20;\nabstract contract Ownable {}\n",
            encoding="utf-8",
        )
        (root / "lib" / "demo" / "lib" / "forge-std" / "src" / "Test.sol").write_text(
            "pragma solidity ^0.8.20;\ncontract Test {}\n",
            encoding="utf-8",
        )
        return tmp, root

    def test_help(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(helper.main(["--h"]), 0)
        rendered = out.getvalue()
        self.assertIn("LOWKEY // IMPORT HELPER", rendered)
        self.assertIn("IMPORT SYNTAX CHEAT SHEET:", rendered)
        self.assertIn('import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";', rendered)
        self.assertIn('import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";', rendered)

    def test_remapping(self):
        tmp, root = self.project()
        try:
            maps = helper.remappings(root)
            p = root / "lib/demo/src/Ownable.sol"
            self.assertEqual(helper.import_path(p, root, maps), "demo/Ownable.sol")
        finally:
            tmp.cleanup()

    def test_package_prefix_ignores_nested_dependency_mapping(self):
        tmp, root = self.project()
        try:
            maps = helper.remappings(root)
            pkgs = helper.packages(root, maps)
            self.assertEqual(pkgs[0].prefix, "demo/")
            files = list(helper.sol_files(root / "lib" / "demo"))
            self.assertEqual([p.relative_to(root / "lib" / "demo").as_posix() for p in files], ["src/Ownable.sol"])
        finally:
            tmp.cleanup()

    def test_file_scope_symbols(self):
        tmp, root = self.project()
        try:
            syms = helper.extract(root / "src/A.sol", root, helper.remappings(root))
            names = {(s.kind, s.name) for s in syms}
            for expected in [
                ("contract", "A"),
                ("interface", "IA"),
                ("library", "ALib"),
                ("struct", "Data"),
                ("enum", "State"),
                ("type", "Amount"),
                ("error", "Bad"),
                ("constant", "LIMIT"),
            ]:
                self.assertIn(expected, names)
        finally:
            tmp.cleanup()

    def test_search_tokens_accept_solidity_import_declaration(self):
        self.assertEqual(
            helper.search_tokens(
                'import {ERC721URIStorage, ERC721} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";'
            ),
            ["erc721uristorage", "erc721"],
        )
        self.assertEqual(helper.search_tokens("ERC721URIStorage,"), ["erc721uristorage"])

    def test_choose_exact_symbol_search_accepts_trailing_punctuation(self):
        tmp, root = self.project()
        try:
            a = helper.Symbol("ERC721", "contract", root / "src/A.sol", "demo/ERC721.sol", 1)
            b = helper.Symbol("ERC721URIStorage", "contract", root / "src/A.sol", "demo/ERC721URIStorage.sol", 1)
            with patch("builtins.input", side_effect=["/ERC721URIStorage,"]):
                selected = helper.choose([a, b], helper.sym_render, "symbols")
            self.assertEqual(selected.name, "ERC721URIStorage")
        finally:
            tmp.cleanup()

    def test_direct_import_query_finds_symbol_without_category(self):
        tmp, root = self.project()
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                result = helper.run_category("Ownable", root, helper.remappings(root))
            rendered = out.getvalue()
            self.assertEqual(result, 0)
            self.assertIn("NAME:   Ownable", rendered)
            self.assertIn("IMPORT: import {Ownable} from", rendered)
        finally:
            tmp.cleanup()

    def test_combines_symbols_from_same_source_file(self):
        tmp, root = self.project()
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                result = helper.run_category(
                    'import {A, Data} from "demo/A.sol";',
                    root,
                    helper.remappings(root),
                )
            rendered = out.getvalue()
            self.assertEqual(result, 0)
            self.assertIn('RESOLVED 2 SYMBOL(S)', rendered)
            self.assertIn('import {A, Data} from "demo/A.sol";', rendered)
            self.assertNotIn("separate valid imports", rendered)
        finally:
            tmp.cleanup()

    def test_splits_symbols_when_pasted_path_is_not_the_defining_source(self):
        tmp, root = self.project()
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                result = helper.run_category(
                    'import {A, Ownable} from "demo/A.sol";',
                    root,
                    helper.remappings(root),
                )
            rendered = out.getvalue()
            self.assertEqual(result, 0)
            self.assertIn('import {A} from "demo/A.sol";', rendered)
            self.assertIn('import {Ownable} from "demo/Ownable.sol";', rendered)
            self.assertIn("separate valid imports", rendered)
        finally:
            tmp.cleanup()

    def test_preserves_named_import_aliases(self):
        tmp, root = self.project()
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                result = helper.run_category(
                    'import {A as Foo, Data as Bar} from "demo/A.sol";',
                    root,
                    helper.remappings(root),
                )
            rendered = out.getvalue()
            self.assertEqual(result, 0)
            self.assertIn('import {A as Foo, Data as Bar} from "demo/A.sol";', rendered)
        finally:
            tmp.cleanup()

    def test_resolves_direct_source_path_query(self):
        tmp, root = self.project()
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                result = helper.run_category("demo/A.sol", root, helper.remappings(root))
            rendered = out.getvalue()
            self.assertEqual(result, 0)
            self.assertIn("IMPORT FILE: demo/A.sol", rendered)
            self.assertIn("A [contract]", rendered)
            self.assertIn("Data [struct]", rendered)
        finally:
            tmp.cleanup()

    def test_preserves_namespace_import_alias(self):
        tmp, root = self.project()
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                result = helper.run_category(
                    'import * as Utils from "demo/A.sol";',
                    root,
                    helper.remappings(root),
                )
            rendered = out.getvalue()
            self.assertEqual(result, 0)
            self.assertIn('import * as Utils from "demo/A.sol";', rendered)
        finally:
            tmp.cleanup()

    def test_offers_fuzzy_suggestion_for_import_search(self):
        tmp, root = self.project()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            result = helper.run_category("Ownabl", root, helper.remappings(root))
        rendered = out.getvalue()
        self.assertEqual(result, 2)
        self.assertIn("Did you mean:", rendered)
        self.assertIn("Ownable", rendered)


if __name__ == "__main__":
    unittest.main()
