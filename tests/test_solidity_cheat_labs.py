import subprocess
import shutil
import tempfile
import unittest
from pathlib import Path

from lowkey.solidity_cheat_data import CONTRACT_LABS


class SolidityCheatLabCompileTests(unittest.TestCase):
    """Compile every explicit standalone cheat lab in its own tiny Foundry project."""

    def test_standalone_labs_compile(self):
        if shutil.which("forge") is None:
            self.skipTest("Forge is required for Solidity lab compilation tests")
        for name, source in CONTRACT_LABS.items():
            with self.subTest(lab=name), tempfile.TemporaryDirectory(
                prefix=f"lowkey-cheat-{name}-"
            ) as td:
                root = Path(td)
                src = root / "src"
                src.mkdir()

                (root / "foundry.toml").write_text(
                    """[profile.default]
src = "src"
solc_version = "0.8.20"
""",
                    encoding="utf-8",
                )

                safe = "".join(ch if ch.isalnum() else "_" for ch in name)
                (src / f"{safe}.sol").write_text(
                    """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

"""
                    + source
                    + "\n",
                    encoding="utf-8",
                )

                proc = subprocess.run(
                    ["forge", "build", "--root", str(root)],
                    text=True,
                    capture_output=True,
                )

                self.assertEqual(
                    proc.returncode,
                    0,
                    f"Lab {name} failed to compile:\n"
                    f"{proc.stdout}\n{proc.stderr}",
                )


if __name__ == "__main__":
    unittest.main()
