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

    @patch("clone_tools.git_repo_ready", return_value=False)
    @patch("clone_tools.ensure_cache_repo")
    @patch("clone_tools.run_git")
    def test_update_one_level_uses_cache_and_jobs(
        self, run_git, ensure_cache, _ready
    ):
        ensure_cache.return_value = Path("/tmp/forge-std-cache.git")
        run_git.return_value = MagicMock(returncode=0)
        repo = Path("/tmp/project")
        entries = [
            (
                "https://github.com/foundry-rs/forge-std",
                "a" * 40,
                repo / "lib" / "forge-std",
            )
        ]
        self.assertEqual(
            clone_tools.update_one_level(repo, entries, jobs=8, use_cache=True),
            0,
        )
        command = run_git.call_args.args[0]
        self.assertIn("submodule", command)
        self.assertIn("update", command)
        self.assertIn("--init", command)
        self.assertIn("--jobs", command)
        self.assertIn("8", command)
        self.assertIn("--depth", command)
        self.assertIn("1", command)
        self.assertIn("--reference-if-able", command)
        self.assertIn("/tmp/forge-std-cache.git", command)

    @patch("clone_tools.cache_submodule", return_value=True)
    @patch("clone_tools.git_repo_ready", return_value=True)
    def test_populate_level_cache(self, _ready, cache_submodule):
        repo = Path("/tmp/project/lib/forge-std")
        entries = [
            (
                "https://github.com/foundry-rs/forge-std",
                "a" * 40,
                repo,
            )
        ]
        clone_tools.populate_level_cache(entries, use_cache=True)
        cache_submodule.assert_called_once_with(
            "https://github.com/foundry-rs/forge-std",
            repo,
            "a" * 40,
        )


if __name__ == "__main__":
    unittest.main()
