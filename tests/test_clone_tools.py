import importlib.util
import pathlib
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "clone_tools.py"
spec = importlib.util.spec_from_file_location("clone_tools", MODULE)
clone_tools = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = clone_tools
spec.loader.exec_module(clone_tools)


class LowkeyCloneTests(unittest.TestCase):
    def test_repo_name_from_http_and_ssh_urls(self):
        self.assertEqual(
            clone_tools.repo_name_from_url(
                "https://github.com/CodeHawks-Contests/contest.git"
            ),
            "contest",
        )
        self.assertEqual(
            clone_tools.repo_name_from_url("git@github.com:owner/project.git"),
            "project",
        )

    def test_parse_defaults_to_shallow_and_parallel(self):
        url, destination, depth, jobs, use_cache = clone_tools.parse_clone_args(
            ["https://github.com/owner/project.git"]
        )
        self.assertEqual(url, "https://github.com/owner/project.git")
        self.assertIsNone(destination)
        self.assertEqual(depth, 1)
        self.assertGreaterEqual(jobs, 2)
        self.assertLessEqual(jobs, 8)
        self.assertTrue(use_cache)

    def test_parse_clone_options(self):
        parsed = clone_tools.parse_clone_args(
            [
                "https://github.com/owner/project.git",
                "my-project",
                "--jobs=6",
                "--depth=3",
                "--no-cache",
            ]
        )
        self.assertEqual(
            parsed,
            ("https://github.com/owner/project.git", "my-project", 3, 6, False),
        )

    @patch("clone_tools.ensure_cache_repo")
    @patch("clone_tools.cache_has_objects", return_value=True)
    @patch("clone_tools.run_git")
    def test_update_submodules_uses_parallel_shallow_cached_mode(
        self, run_git, _has_objects, ensure_cache
    ):
        ensure_cache.return_value = Path("/tmp/lowkey-cache.git")
        run_git.return_value = MagicMock(returncode=0)
        self.assertEqual(
            clone_tools.update_submodules(
                Path("/tmp/project"), depth=1, jobs=6, use_cache=True
            ),
            0,
        )
        command = run_git.call_args.args[0]
        self.assertIn("--recursive", command)
        self.assertIn("--jobs", command)
        self.assertIn("6", command)
        self.assertIn("--depth", command)
        self.assertIn("1", command)
        self.assertIn("--shallow-submodules", command)
        self.assertIn("--reference-if-able", command)
        self.assertIn("--dissociate", command)

    @patch("clone_tools.ensure_cache_repo")
    @patch("clone_tools.run_git")
    def test_update_submodules_without_cache(self, run_git, ensure_cache):
        run_git.return_value = MagicMock(returncode=0)
        self.assertEqual(
            clone_tools.update_submodules(
                Path("/tmp/project"), depth=1, jobs=4, use_cache=False
            ),
            0,
        )
        ensure_cache.assert_not_called()
        command = run_git.call_args.args[0]
        self.assertNotIn("--reference-if-able", command)
        self.assertNotIn("--dissociate", command)


if __name__ == "__main__":
    unittest.main()
