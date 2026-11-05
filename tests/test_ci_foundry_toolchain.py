from __future__ import annotations

import unittest

from scripts.verify_foundry_toolchain import reported_version, version_matches


class FoundryToolchainVersionTests(unittest.TestCase):
    def test_accepts_exact_pinned_version(self):
        output = "forge Version: 1.9.0\nCommit SHA: abc123\nBuild Profile: dist"
        self.assertEqual(reported_version(output), "1.9.0")
        self.assertTrue(version_matches(output, "1.9.0"))

    def test_rejects_different_patch_version(self):
        self.assertFalse(version_matches("cast Version: 1.9.1", "1.9.0"))

    def test_rejects_prerelease_and_suffix_versions(self):
        self.assertFalse(version_matches("anvil Version: 1.9.0-rc1", "1.9.0"))

    def test_rejects_missing_version_metadata(self):
        self.assertIsNone(reported_version("forge 1.9.0"))
        self.assertFalse(version_matches("forge 1.9.0", "1.9.0"))


if __name__ == "__main__":
    unittest.main()
