
from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "lk.py"
sys.path.insert(0, str(ROOT / "lowkey"))
spec = importlib.util.spec_from_file_location("lowkeycast_lab_resource_tests", MODULE)
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


class LabResourceBuildRoutingTests(unittest.TestCase):
    def _foundry_project(self, root):
        return {
            "root": str(root),
            "name": root.name,
            "kind": "foundry",
            "backend": "foundry",
            "stacks": ["foundry"],
            "build_backend": "foundry",
        }

    def test_lab_bootstrap_uses_production_scope_planner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with (
                patch.object(lk, "detect_project", return_value=self._foundry_project(root)),
                patch.object(lk, "discover_nested_projects", None),
                patch.object(lk, "workspace_context", None),
                patch.object(lk, "bootstrap_project", return_value=0),
                patch.object(lk, "_run_resource_aware_foundry_build", return_value=0) as planned,
            ):
                result = lk._run_project_build({}, root)

            self.assertEqual(result, 0)
            planned.assert_called_once_with(root, ["--scope", "production"], lab_phase=True)

    def test_lab_build_wrapper_requests_the_two_gib_memory_floor(self):
        class Planner:
            def __init__(self):
                self.options = None

            def run_build(self, args, **kwargs):
                self.options = kwargs
                return 0

        planner = Planner()
        with patch.object(lk, "_foundry_build_planner", return_value=planner):
            result = lk._run_resource_aware_foundry_build(
                pathlib.Path("/project"), ["--scope", "production"], lab_phase=True
            )

        self.assertEqual(result, 0)
        self.assertEqual(
            planner.options["minimum_available_memory_bytes"],
            2 * 1024 ** 3,
        )


    def test_internal_build_dispatch_uses_planner_and_preserves_options(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            args = ["--scope", "production", "--plan"]
            with (
                patch.object(lk, "detected_project_root", return_value=root),
                patch.object(lk, "detect_project", return_value=self._foundry_project(root)),
                patch.object(lk, "bootstrap_project", return_value=0),
                patch.object(lk, "_run_resource_aware_foundry_build", return_value=0) as planned,
            ):
                result = lk.run_native_project_command({}, "build", args)

            self.assertEqual(result, 0)
            planned.assert_called_once_with(root, args)

    def test_installer_and_launcher_publish_the_resource_aware_front_door(self):
        launcher = (ROOT / "bin" / "lk").read_text(encoding="utf-8")
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn('exec python3 "$HOME/.lowkey/foundry_build.py" "$@"', launcher)
        self.assertIn('cp "$STAGE_DIR/foundry_build.py" "$TARGET_LOWKEY_DIR/foundry_build.py"', installer)
        self.assertIn('"$TARGET_BIN_DIR/lk" build --help', installer)

    def test_fixture_execution_scopes_foundry_test_root_and_restores_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            original_present = "FOUNDRY_TEST" in lk.os.environ
            original = lk.os.environ.get("FOUNDRY_TEST")
            captured = {}

            def fake_run_foundry(args, capture=False, cwd=None):
                captured["args"] = args
                captured["cwd"] = cwd
                captured["test_root"] = lk.os.environ.get("FOUNDRY_TEST")
                return lk.CommandResult("fixture ran", 0)

            try:
                lk.os.environ["FOUNDRY_TEST"] = "original-tests"
                with patch.object(lk, "run_foundry", side_effect=fake_run_foundry):
                    result = lk._run_scoped_lab_fixture_test(
                        root, ".audit/lab/Fixture.t.sol", "Fixture", 1
                    )
                self.assertEqual(result.code, 0)
                self.assertEqual(captured["test_root"], ".audit/lab")
                self.assertIn("--threads", captured["args"])
                self.assertIn("1", captured["args"])
                self.assertEqual(captured["args"].count(".audit/lab/Fixture.t.sol"), 1)
                self.assertNotIn("--match-path", captured["args"])
                self.assertEqual(lk.os.environ.get("FOUNDRY_TEST"), "original-tests")
            finally:
                if original_present:
                    lk.os.environ["FOUNDRY_TEST"] = original or ""
                else:
                    lk.os.environ.pop("FOUNDRY_TEST", None)

    def test_fixture_execution_restores_absent_foundry_test_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            original_present = "FOUNDRY_TEST" in lk.os.environ
            original = lk.os.environ.get("FOUNDRY_TEST")
            lk.os.environ.pop("FOUNDRY_TEST", None)
            try:
                with patch.object(
                    lk, "run_foundry",
                    side_effect=lambda *args, **kwargs: lk.CommandResult("fixture ran", 0),
                ):
                    lk._run_scoped_lab_fixture_test(
                        root, ".audit/lab/Fixture.t.sol", "Fixture", 1
                    )
                self.assertNotIn("FOUNDRY_TEST", lk.os.environ)
            finally:
                if original_present:
                    lk.os.environ["FOUNDRY_TEST"] = original or ""
                else:
                    lk.os.environ.pop("FOUNDRY_TEST", None)

    def test_build_wrapper_fails_closed_when_planner_is_missing(self):
        with patch.object(lk, "_foundry_build_planner", side_effect=RuntimeError("planner missing")):
            result = lk._run_resource_aware_foundry_build(
                pathlib.Path("/project"), ["--scope", "production"]
            )
        self.assertNotEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
