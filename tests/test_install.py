import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALL = ROOT / "install.sh"


class InstallSmokeTests(unittest.TestCase):
    def test_install_publishes_current_runtime_and_manifest(self):
        with tempfile.TemporaryDirectory() as home:
            env = os.environ.copy()
            env["HOME"] = home

            result = subprocess.run(
                ["bash", str(INSTALL)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            installed_lk = pathlib.Path(home) / ".foundry" / "bin" / "lk"
            manifest = pathlib.Path(home) / ".lowkey" / "install-manifest.json"
            self.assertTrue(installed_lk.exists())
            self.assertTrue(manifest.exists())

            version = subprocess.run(
                [str(installed_lk), "--version"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(version.returncode, 0, version.stdout + version.stderr)
            self.assertIn("LowkeyCast 2.1", version.stdout)
            self.assertIn("Runtime: OK", version.stdout)

            help_result = subprocess.run(
                [str(installed_lk), "--help"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(help_result.returncode, 0, help_result.stderr)
            self.assertIn("lk slither", help_result.stdout)
            self.assertIn("lk audit run", help_result.stdout)


if __name__ == "__main__":
    unittest.main()
