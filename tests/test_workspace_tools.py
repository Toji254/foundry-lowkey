from __future__ import annotations

import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))

import project_detection
import workspace_tools


class WorkspaceToolsTests(unittest.TestCase):
    def write(self, root, relative, text):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def workspace(self, root):
        self.write(root, "package.json", '{"private": true, "workspaces": ["packages/*"]}')
        self.write(root, "packages/perps/foundry.toml", '[profile.default]\nsrc = "src"\ntest = "test"\nscript = "script"\n')
        self.write(root, "packages/perps/src/Perps.sol", "contract Perps {}")
        self.write(root, "packages/perps/test/Perps.t.sol", "contract PerpsTest {}")
        self.write(root, "packages/perps/script/Deploy.s.sol", "contract Deploy {}")
        self.write(root, "packages/shared/foundry.toml", '[profile.default]\nsrc = "src"\n')
        self.write(root, "packages/shared/src/Shared.sol", "library Shared {}")
        self.write(root, "packages/perps/remappings.txt", "@shared/=../shared/src/\n")

    def test_workspace_overview_lists_members_and_separate_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.workspace(root)

            data = workspace_tools.workspace_overview(root)

            self.assertEqual(data["member_count"], 2)
            members = {item["path"]: item for item in data["members"]}
            self.assertEqual(members["packages/perps"]["source_files"], 1)
            self.assertEqual(members["packages/perps"]["test_files"], 1)
            self.assertEqual(members["packages/perps"]["script_files"], 1)
            self.assertEqual(members["packages/shared"]["source_files"], 1)
            self.assertEqual(members["packages/shared"]["role"], "shared first-party package")
            self.assertEqual(members["packages/shared"]["used_by"], ["packages/perps"])

    def test_member_selection_accepts_stable_path_and_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.workspace(root)

            self.assertEqual(
                workspace_tools.resolve_member(root, "packages/perps"),
                (root / "packages/perps").resolve(),
            )
            self.assertEqual(
                workspace_tools.resolve_member(root, "shared"),
                (root / "packages/shared").resolve(),
            )
            indexed = workspace_tools.resolve_member(root, "1")
            self.assertIn(indexed, {
                (root / "packages/perps").resolve(),
                (root / "packages/shared").resolve(),
            })

    def test_select_persists_workspace_local_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.workspace(root)

            result = workspace_tools.main(["select", "packages/perps", "--root", str(root)])

            self.assertEqual(result, 0)
            self.assertEqual(
                project_detection.workspace_selection(root),
                (root / "packages/perps").resolve(),
            )
            self.assertTrue((root / ".audit" / "workspace.json").is_file())

    def test_plain_project_overview_requires_workspace_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.workspace(root)
            with self.assertRaises(ValueError):
                workspace_tools.workspace_overview(root / "packages/perps")


if __name__ == "__main__":
    unittest.main()
