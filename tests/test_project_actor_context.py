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
        (root / "foundry.toml").write_text("[profile.default]" + chr(10), encoding="utf-8")
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
        with (
            patch.object(lk, "project_fixture_rpc_info", return_value=None),
            patch.object(lk, "anvil_rpc_info", return_value={}),
        ):
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



    def _session(self, root, name, session_id, rpc, deployer, genesis):
        import hashlib
        return {
            "id": session_id,
            "name": name,
            "project_id": hashlib.sha256(str(root.resolve()).encode()).hexdigest(),
            "rpc": rpc,
            "chain_id": 31337,
            "genesis_hash": genesis,
            "identity_block_hash": genesis,
            "identity_block_number": 0,
            "actors": {"lab-deployer": deployer},
            "active_actor": "lab-deployer",
        }

    def _remembered_network_target(self, root, address, session):
        lk.audit_context.set_target(
            root, address=address, contract="Vault", source="manual"
        )
        config = self._config()
        config["target"] = address
        config["target_contract"] = "Vault"
        config["project_target_registry"] = {
            str(root.resolve()): {
                "Vault": {
                    "address": address,
                    "artifact": None,
                    "explicit": True,
                    "network": {
                        "project_id": session["project_id"],
                        "network_session_id": session["id"],
                        "chain_id": session["chain_id"],
                        "genesis_hash": session["genesis_hash"],
                        "identity_block_hash": session["identity_block_hash"],
                        "identity_block_number": session["identity_block_number"],
                    },
                }
            }
        }
        return config

    def test_target_remembered_on_session_a_is_not_restored_on_session_b(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp, "VaultProject")
            address = "0x" + "11" * 20
            session_a = self._session(root, "dev-a", "session-a", "http://127.0.0.1:18545", "0x" + "aa" * 20, "0x" + "ab" * 32)
            session_b = self._session(root, "dev-b", "session-b", "http://127.0.0.1:18546", "0x" + "bb" * 20, "0x" + "ab" * 32)
            config = self._remembered_network_target(root, address, session_a)
            manager = __import__("unittest").mock.Mock()
            manager.list.return_value = [session_a, session_b]
            manager.active.return_value = session_b
            with (
                patch.object(lk, "project_fixture_rpc_info", return_value=None),
                patch.object(lk, "anvil_rpc_info", return_value={}),
                patch.object(lk, "_project_network_manager", return_value=manager),
            ):
                resolved = lk.activate_project_context(config, root)
            self.assertIsNone(resolved["target"])
            self.assertIn("not proven to belong", resolved["target_selection_error"])
            self.assertIsNone(config["target"])
            self.assertEqual(config["_active_network_session"]["id"], "session-b")

    def test_target_is_restored_when_active_session_identity_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp, "VaultProject")
            address = "0x" + "11" * 20
            session = self._session(root, "dev-a", "session-a", "http://127.0.0.1:18545", "0x" + "aa" * 20, "0x" + "ab" * 32)
            config = self._remembered_network_target(root, address, session)
            manager = __import__("unittest").mock.Mock()
            manager.list.return_value = [session]
            manager.active.return_value = session
            with (
                patch.object(lk, "project_fixture_rpc_info", return_value=None),
                patch.object(lk, "anvil_rpc_info", return_value={}),
                patch.object(lk, "_project_network_manager", return_value=manager),
            ):
                resolved = lk.activate_project_context(config, root)
            self.assertEqual(resolved["target"]["address"], address)
            self.assertNotIn("target_selection_error", resolved)
            self.assertEqual(config["target"], address)

    def test_legacy_unbound_target_is_not_silently_borrowed_by_managed_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp, "VaultProject")
            address = "0x" + "11" * 20
            session = self._session(root, "dev-b", "session-b", "http://127.0.0.1:18546", "0x" + "bb" * 20, "0x" + "ab" * 32)
            config = self._remembered_network_target(root, address, session)
            config["project_target_registry"][str(root.resolve())]["Vault"].pop("network")
            manager = __import__("unittest").mock.Mock()
            manager.list.return_value = [session]
            manager.active.return_value = session
            with (
                patch.object(lk, "project_fixture_rpc_info", return_value=None),
                patch.object(lk, "anvil_rpc_info", return_value={}),
                patch.object(lk, "_project_network_manager", return_value=manager),
            ):
                resolved = lk.activate_project_context(config, root)
            self.assertIsNone(resolved["target"])
            self.assertIn("Re-select the target explicitly", resolved["target_selection_error"])

    def test_remembering_target_persists_current_managed_session_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp, "VaultProject")
            address = "0x" + "11" * 20
            session = self._session(root, "dev-a", "session-a", "http://127.0.0.1:18545", "0x" + "aa" * 20, "0x" + "ab" * 32)
            config = self._config()
            config["_active_network_session"] = session
            lk.remember_project_target(config, root, "Vault", address)
            record = config["project_target_registry"][str(root.resolve())]["Vault"]
            self.assertEqual(record["network"]["network_session_id"], "session-a")
            self.assertEqual(record["network"]["project_id"], session["project_id"])
            self.assertEqual(record["network"]["chain_id"], 31337)
            self.assertEqual(record["network"]["genesis_hash"], session["genesis_hash"])

    def test_named_target_from_another_session_is_rejected_but_literal_address_is_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp, "VaultProject")
            address = "0x" + "11" * 20
            explicit = "0x" + "22" * 20
            session_a = self._session(root, "dev-a", "session-a", "http://127.0.0.1:18545", "0x" + "aa" * 20, "0x" + "ab" * 32)
            session_b = self._session(root, "dev-b", "session-b", "http://127.0.0.1:18546", "0x" + "bb" * 20, "0x" + "ab" * 32)
            config = self._remembered_network_target(root, address, session_a)
            config["_active_network_session"] = session_b
            with patch.object(lk, "_project_target_entries", return_value=[{
                "name": "Vault", "contract": "Vault", "address": address,
                "source": "project-config", "artifact": None,
            }]), patch.object(lk, "_target_entry_is_protocol", return_value=True):
                self.assertIsNone(lk.resolve_target_ref(config, "Vault", root))
                self.assertEqual(lk.resolve_target_ref(config, explicit, root), explicit)


    def test_session_bound_target_is_not_restored_when_no_session_is_selected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp, "VaultProject")
            address = "0x" + "11" * 20
            session = self._session(root, "dev-a", "session-a", "http://127.0.0.1:18545", "0x" + "aa" * 20, "0x" + "ab" * 32)
            config = self._remembered_network_target(root, address, session)
            manager = __import__("unittest").mock.Mock()
            manager.list.return_value = [session]
            manager.active.return_value = None
            with (
                patch.object(lk, "project_fixture_rpc_info", return_value=None),
                patch.object(lk, "anvil_rpc_info", return_value={}),
                patch.object(lk, "_project_network_manager", return_value=manager),
            ):
                resolved = lk.activate_project_context(config, root)
            self.assertIsNone(resolved["target"])
            self.assertIn("managed network is registered", resolved["target_selection_error"].lower())
            self.assertIsNone(config["target"])

if __name__ == "__main__":
    unittest.main()
