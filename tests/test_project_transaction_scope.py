import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "lk.py"
spec = importlib.util.spec_from_file_location("lowkeycast_project_transaction_scope", MODULE)
lk = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(lk)


class ProjectTransactionScopeTests(unittest.TestCase):
    def _project(self, base, name="telephone"):
        root = pathlib.Path(base) / name
        root.mkdir()
        (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
        return root

    def test_project_latest_transaction_is_used_when_target_and_rpc_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            target = "0x" + "1" * 40
            tx_hash = "0x" + "a" * 64
            rpc = "http://127.0.0.1:8545"
            with patch.object(lk.audit_context, "foundry_project_root", return_value=root), \
                 patch.object(lk, "active_project_target", return_value=target), \
                 patch.object(lk, "effective_rpc", return_value=rpc):
                lk.audit_context.set_latest(root, tx_hash=tx_hash, target=target, rpc=rpc)
                self.assertEqual(
                    lk.last_transaction({"target": target, "last_tx": "0x" + "b" * 64}),
                    tx_hash,
                )

    def test_project_latest_transaction_for_another_target_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            telephone = "0x" + "1" * 40
            coinflip = "0x" + "2" * 40
            tx_hash = "0x" + "a" * 64
            rpc = "http://127.0.0.1:8545"
            with patch.object(lk.audit_context, "foundry_project_root", return_value=root), \
                 patch.object(lk, "active_project_target", return_value=telephone), \
                 patch.object(lk, "effective_rpc", return_value=rpc):
                lk.audit_context.set_latest(root, tx_hash=tx_hash, target=coinflip, rpc=rpc)
                self.assertIsNone(lk.last_transaction({"target": telephone}))

    def test_unscoped_global_coinflip_transaction_is_not_reused_in_telephone(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            telephone = "0x" + "1" * 40
            coinflip = "0x" + "2" * 40
            tx_hash = "0x" + "a" * 64
            rpc = "http://127.0.0.1:8545"
            config = {"target": telephone, "last_tx": tx_hash}
            with patch.object(lk.audit_context, "foundry_project_root", return_value=root), \
                 patch.object(lk, "active_project_target", return_value=telephone), \
                 patch.object(lk, "effective_rpc", return_value=rpc), \
                 patch.object(lk, "rpc_json", return_value={"to": coinflip}):
                self.assertIsNone(lk.last_transaction(config))

    def test_legacy_global_transaction_is_migrated_only_when_destination_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            telephone = "0x" + "1" * 40
            tx_hash = "0x" + "a" * 64
            rpc = "http://127.0.0.1:8545"
            config = {"target": telephone, "last_tx": tx_hash}
            with patch.object(lk.audit_context, "foundry_project_root", return_value=root), \
                 patch.object(lk, "active_project_target", return_value=telephone), \
                 patch.object(lk, "effective_rpc", return_value=rpc), \
                 patch.object(lk, "rpc_json", return_value={"to": telephone}):
                self.assertEqual(lk.last_transaction(config), tx_hash)
                latest = lk.audit_context.load(root)["latest"]
                self.assertEqual(latest["tx_hash"], tx_hash)
                self.assertEqual(latest["target"], telephone)
                self.assertEqual(latest["rpc"], rpc)

    def test_legacy_hash_is_not_migrated_without_a_current_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            config = {"last_tx": "0x" + "a" * 64}
            with patch.object(lk.audit_context, "foundry_project_root", return_value=root), \
                 patch.object(lk, "active_project_target", return_value=None), \
                 patch.object(lk, "effective_rpc", return_value="http://127.0.0.1:8545"):
                self.assertIsNone(lk.last_transaction(config))


if __name__ == "__main__":
    unittest.main()
