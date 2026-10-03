import contextlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "import_helper.py"
spec = importlib.util.spec_from_file_location("lowkey_import_helper", MODULE)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

class ImportHelperTests(unittest.TestCase):
    def project(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        (root / "src").mkdir()
        (root / "lib" / "demo" / "src").mkdir(parents=True)
        (root / "foundry.toml").write_text('[profile.default]\nsrc="src"\nlibs=["lib"]\n', encoding="utf-8")
        (root / "remappings.txt").write_text("demo/=lib/demo/src/\n", encoding="utf-8")
        (root / "src" / "A.sol").write_text(
            "pragma solidity ^0.8.20;\ncontract A {}\ninterface IA {}\nlibrary ALib {}\n"
            "struct Data { uint256 x; }\nenum State { A, B }\ntype Amount is uint256;\n"
            "error Bad();\nuint256 constant LIMIT = 1;\n", encoding="utf-8"
        )
        (root / "lib" / "demo" / "src" / "Ownable.sol").write_text(
            "pragma solidity ^0.8.20;\nabstract contract Ownable {}\n", encoding="utf-8"
        )
        return tmp, root

    def test_help(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(helper.main(["--h"]), 0)
        self.assertIn("LOWKEY // IMPORT HELPER", out.getvalue())

    def test_remapping(self):
        tmp, root = self.project()
        try:
            maps = helper.remappings(root)
            p = root / "lib/demo/src/Ownable.sol"
            self.assertEqual(helper.import_path(p, root, maps), "demo/Ownable.sol")
        finally:
            tmp.cleanup()

    def test_file_scope_symbols(self):
        tmp, root = self.project()
        try:
            syms = helper.extract(root / "src/A.sol", root, helper.remappings(root))
            names = {(s.kind, s.name) for s in syms}
            for expected in [("contract","A"),("interface","IA"),("library","ALib"),("struct","Data"),("enum","State"),("type","Amount"),("error","Bad"),("constant","LIMIT")]:
                self.assertIn(expected, names)
        finally:
            tmp.cleanup()

if __name__ == "__main__":
    unittest.main()
