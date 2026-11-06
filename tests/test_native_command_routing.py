import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "lowkey") not in sys.path:
    sys.path.insert(0, str(ROOT / "lowkey"))

import bootstrap


class NativeCommandPlannerTests(unittest.TestCase):
    def _project(self, manifest, source=None):
        tmp=tempfile.TemporaryDirectory()
        root=Path(tmp.name)
        for path, content in manifest.items():
            p=root/path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        if source:
            p=root/source[0]
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(source[1], encoding="utf-8")
        return tmp, root

    def test_package_test_script_uses_declared_manager(self):
        tmp, root=self._project({
            "package.json": json.dumps({"scripts":{"test":"hardhat test"}})
        })
        try:
            with patch.object(bootstrap.shutil, "which", side_effect=lambda name: "/usr/bin/npm" if name == "npm" else None):
                result=bootstrap.project_test_command({"root": str(root), "backend":"node"}, root)
            self.assertEqual(result[1], ["npm", "run", "test"])
        finally:
            tmp.cleanup()

    def test_foundry_test(self):
        tmp, root=self._project({"foundry.toml":"[profile.default]\n"})
        try:
            result=bootstrap.project_test_command({"root":str(root),"backend":"foundry"}, root)
            self.assertEqual(result[1], ["forge","test"])
        finally:
            tmp.cleanup()

    def test_anchor_test(self):
        tmp, root=self._project({"Anchor.toml":"[provider]\ncluster = \"localnet\"\n"})
        try:
            with patch.object(bootstrap.shutil, "which", side_effect=lambda name: "/usr/bin/anchor" if name == "anchor" else None):
                result=bootstrap.project_test_command({"root":str(root),"backend":"solana-anchor"}, root)
            self.assertEqual(result[1], ["anchor","test"])
        finally:
            tmp.cleanup()

    def test_cargo_test(self):
        tmp, root=self._project({"Cargo.toml":"[package]\nname=\"demo\"\nversion=\"0.1.0\"\n"})
        try:
            with patch.object(bootstrap.shutil, "which", side_effect=lambda name: "/usr/bin/cargo" if name == "cargo" else None):
                result=bootstrap.project_test_command({"root":str(root),"backend":"cargo"}, root)
            self.assertEqual(result[1][0:2], ["cargo","test"])
        finally:
            tmp.cleanup()

    def test_python_pytest_requires_tests(self):
        tmp, root=self._project({
            "pyproject.toml":"[project]\nname=\"demo\"\nversion=\"0.1.0\"\n",
            "tests/test_smoke.py":"def test_smoke(): pass\n",
        })
        try:
            with patch.object(bootstrap.shutil, "which", side_effect=lambda name: "/usr/bin/uv" if name == "uv" else None):
                result=bootstrap.project_test_command({"root":str(root),"backend":"python"}, root)
            self.assertEqual(result[1], ["uv","run","pytest"])
        finally:
            tmp.cleanup()

class NativeBuildPlannerTests(unittest.TestCase):
    def test_cosmwasm_build_uses_cargo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                '[package]\nname="cw"\nversion="0.1.0"\n[dependencies]\ncosmwasm-std="2"\n',
                encoding="utf-8",
            )
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text("pub fn x() {}\n", encoding="utf-8")
            with patch.object(bootstrap.shutil, "which", side_effect=lambda name: "/usr/bin/cargo" if name == "cargo" else None):
                result = bootstrap.project_build_command({"root": str(root), "backend": "cosmwasm"}, root)
            self.assertIsNotNone(result)
            self.assertEqual(result[1][0:2], ["cargo", "build"])


class LauncherRoutingTests(unittest.TestCase):
    def test_build_and_test_are_not_short_circuited_to_forge(self):
        launcher = (Path(__file__).resolve().parents[1] / "bin" / "lk").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("build|test|", launcher)
        self.assertNotIn("|build|", launcher)
        self.assertNotIn("|test|", launcher)



if __name__ == "__main__":
    unittest.main()
