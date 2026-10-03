import subprocess
import tempfile
import unittest
from pathlib import Path

from lowkey.solidity_cheat_data import CONTRACT_LABS


class SolidityCheatLabCompileTests(unittest.TestCase):
    """Compile every explicit standalone cheat lab in one Foundry project."""

    def test_standalone_labs_compile(self):
        with tempfile.TemporaryDirectory(prefix="lowkey-cheat-labs-") as td:
            root = Path(td)
            src = root / "src"
            src.mkdir()
            (root / "foundry.toml").write_text(
                '[profile.default]\nsrc = "src"\nsolc_version = "0.8.20"\n',
                encoding="utf-8",
            )
            for name, source in CONTRACT_LABS.items():
                safe = "".join(ch if ch.isalnum() else "_" for ch in name)
                (src / f"{safe}.sol").write_text(
                    "// SPDX-License-Identifier: UNLICENSED\n"
                    "pragma solidity ^0.8.20;\n\n" + source + "\n",
                    encoding="utf-8",
                )
            proc = subprocess.run(
                ["forge", "build", "--root", str(root), "--offline"],
                text=True,
                capture_output=True,
            )
            self.assertEqual(
                proc.returncode,
                0,
                f"standalone cheat labs failed to compile:\n{proc.stdout}\n{proc.stderr}",
            )


if __name__ == "__main__":
    unittest.main()
