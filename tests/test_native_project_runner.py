import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "project_detection.py"

spec = importlib.util.spec_from_file_location("project_detection", MODULE)
project_detection = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(project_detection)


class NativeProjectRunnerTests(unittest.TestCase):
    def test_uv_project_prefers_uv_run_pytest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "pyproject.toml").write_text("[project]\nname = \"demo\"\n", encoding="utf-8")

            with patch.object(
                project_detection.shutil,
                "which",
                side_effect=lambda name: "/usr/bin/uv" if name == "uv" else None,
            ):
                self.assertEqual(
                    project_detection._python_test_command(root),
                    ["/usr/bin/uv", "run", "pytest", "-q"],
                )

    def test_local_venv_is_used_without_uv(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            python = root / ".venv" / "bin" / "python"
            python.parent.mkdir(parents=True)
            python.write_text("", encoding="utf-8")

            with patch.object(
                project_detection.shutil,
                "which",
                side_effect=lambda name: None,
            ):
                self.assertEqual(
                    project_detection._python_test_command(root),
                    [str(python), "-m", "pytest", "-q"],
                )


if __name__ == "__main__":
    unittest.main()
