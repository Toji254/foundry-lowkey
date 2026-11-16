import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))

import lk


class ProjectActorContextTests(unittest.TestCase):
    def _root(self, parent, name):
        root = pathlib.Path(parent) / name
        root.mkdir()
        (root / "foundry.toml").write_text("[profile.default]\\n", encoding="utf-8")
        return root

    def _config(self, active="Alice"):
        return {
            "actor": active,
            "wallets": {
                "lab-deployer": {"source": "anvil-default", "anvil_index": 0},
                "Alice": {"source": "anvil-default", "anvil_index": 1},
                "Bob": {"source": "anvil-default", "anvil_index": 2},
            },
            "abi_paths": {},
            "target_owners": {},
        }

    def _activate(self, config, root):
        with patch.object(lk, "project_fixture_rpc_info", return_value=None), \\
             patch.object(lk, "anvil_rpc_info", return_value={}):
            return lk.activate_project_context(config, root)

    def test_fresh_project_uses_reserved_lab_deployer_not_previous_global_actor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp, "Token")
            config = self._config(active="Alice")

            resolved = self._activate(config, root)

            self.assertEqual(resolved["actor"], "lab-deployer")
            self.assertEqual(resolved["actor_source"], "project-default")
            self.assertEqual(config["actor"], "lab-deployer")

    def test_active_actor_is_restored_when_switching_between_projects(self):
        with tempfile.TemporaryDirectory() as tmp:
            token = self._root(tmp, "Token")
            escrow = self._root(tmp, "Escrow")
            lk.audit_context.update(
                token, actor="Alice", actor_profile="Alice", actor_scope_initialized=True
            )
            lk.audit_context.update(
                escrow, actor="Bob", actor_profile="Bob", actor_scope_initialized=True
            )
            config = self._config(active="Alice")

            self.assertEqual(self._activate(config, token)["actor"], "Alice")
            self.assertEqual(self._activate(config, escrow)["actor"], "Bob")
            self.assertEqual(self._activate(config, token)["actor"], "Alice")

    def test_ephemeral_actor_override_wins_during_nested_context_activation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp, "Token")
            lk.audit_context.update(
                root, actor="Alice", actor_profile="Alice", actor_scope_initialized=True
            )
            config = self._config(active="Bob")
            config["_ephemeral"] = True

            resolved = self._activate(config, root)

            self.assertEqual(resolved["actor"], "Bob")
            self.assertEqual(resolved["actor_source"], "command-line")
            self.assertEqual(config["actor"], "Bob")

    def test_ephemeral_actor_is_never_persisted_by_dispatch_or_context_sync(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp, "Token")
            lk.audit_context.update(
                root, actor="Alice", actor_profile="Alice", actor_scope_initialized=True
            )
            config = self._config(active="Bob")
            config["_ephemeral"] = True
            self._activate(config, root)

            self.assertIsNone(lk.persist_project_actor(config, root))
            lk._sync_audit_context(config, root)
            stored = lk.audit_context.load(root)

            self.assertEqual(stored["actor_profile"], "Alice")
            self.assertEqual(stored["actor"], "Alice")
            self.assertTrue(stored["actor_scope_initialized"])

    def test_removed_project_actor_does_not_fall_back_to_another_global_actor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp, "Token")
            lk.audit_context.update(
                root,
                actor="Removed profile",
                actor_profile="Removed profile",
                actor_scope_initialized=True,
            )
            config = self._config(active="Bob")

            resolved = self._activate(config, root)

            self.assertIsNone(resolved["actor"])
            self.assertIsNone(config["actor"])


if __name__ == "__main__":
    unittest.main()
