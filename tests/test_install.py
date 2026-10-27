import json
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
            env["XDG_CONFIG_HOME"] = str(pathlib.Path(home) / ".config")
            env["XDG_DATA_HOME"] = str(pathlib.Path(home) / ".local" / "share")
            env["XDG_STATE_HOME"] = str(pathlib.Path(home) / ".local" / "state")

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
            question_engine = pathlib.Path(home) / ".lowkey" / "question_engine.py"
            self.assertTrue(question_engine.exists())
            cheatsheet = pathlib.Path(home) / ".lowkey" / "solidity_cheatsheet.py"
            self.assertTrue(cheatsheet.exists())
            self.assertTrue((pathlib.Path(home) / ".lowkey" / "ai_harness.py").exists())
            self.assertTrue((pathlib.Path(home) / ".lowkey" / "experience_memory.py").exists())

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
            self.assertIn("lk audit --checks", help_result.stdout)
            self.assertIn("lk q", help_result.stdout)
            self.assertIn("lk questions", help_result.stdout)
            self.assertIn("lk cheat", help_result.stdout)
            self.assertIn("lk ai status", help_result.stdout)
            self.assertIn("lk memory status", help_result.stdout)

            ai_status = subprocess.run(
                [str(installed_lk), "ai", "status", "--json"], cwd=ROOT, env=env,
                capture_output=True, text=True,
            )
            self.assertEqual(ai_status.returncode, 0, ai_status.stdout + ai_status.stderr)
            self.assertFalse(json.loads(ai_status.stdout)["enabled"])

            memory_status = subprocess.run(
                [str(installed_lk), "memory", "status"], cwd=ROOT, env=env,
                capture_output=True, text=True,
            )
            self.assertEqual(memory_status.returncode, 0, memory_status.stdout + memory_status.stderr)
            self.assertIn('"global_approved": 0', memory_status.stdout)
            for command in ("forge", "slither"):
                contextual_help = subprocess.run(
                    [str(installed_lk), command, "--h"],
                    cwd=ROOT,
                    env=env,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(contextual_help.returncode, 0, contextual_help.stderr)
                self.assertIn(f"lk {command}", contextual_help.stdout)
                self.assertNotIn("LOWKEY SLITHER", contextual_help.stdout)



if __name__ == "__main__":
    unittest.main()
