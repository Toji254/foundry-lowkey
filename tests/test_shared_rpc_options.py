import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))

import lk


class ExplicitRpcContextTests(unittest.TestCase):
    def test_explicit_rpc_overrides_remembered_project_rpc(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "Token"
            root.mkdir()
            (root / "foundry.toml").write_text("[profile.default]" + chr(10), encoding="utf-8")
            project_rpc = "http://127.0.0.1:8545"
            explicit_rpc = "http://127.0.0.1:9545"
            lk.audit_context.update(root, rpc=project_rpc)
            config = {
                "target": None,
                "_resolved_project_context": {
                    "project_root": str(root),
                    "rpc": project_rpc,
                    "rpc_source": "project",
                },
            }

            with patch.object(lk.audit_context, "foundry_project_root", return_value=root):
                self.assertEqual(lk.effective_rpc(config), project_rpc)
                self.assertEqual(lk.effective_rpc(config, explicit_rpc=explicit_rpc), explicit_rpc)

    def test_send_uses_explicit_rpc_for_post_send_receipt_and_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "Token"
            root.mkdir()
            (root / "foundry.toml").write_text("[profile.default]" + chr(10), encoding="utf-8")
            target = "0x" + "2" * 40
            tx_hash = "0x" + "a" * 64
            project_rpc = "http://127.0.0.1:8545"
            explicit_rpc = "http://127.0.0.1:9545"
            config = {
                "target": target,
                "target_contract": "Token",
                "wallets": {},
                "actor": None,
                "abi_paths": {},
                "rpc": project_rpc,
                "_ephemeral": True,
                "_resolved_project_context": {
                    "project_root": str(root),
                    "rpc": project_rpc,
                    "rpc_source": "project",
                },
            }
            receipt_calls = []
            transaction_calls = []

            def fake_cast(command):
                return 0, "transactionHash: " + tx_hash, ""

            def fake_receipt(rpc, tx):
                receipt_calls.append((rpc, tx))
                return {"status": "0x1"}

            def fake_rpc_json(rpc, method, params):
                transaction_calls.append((rpc, method))
                return {"to": target, "from": "0x" + "1" * 40}

            with patch.object(lk.audit_context, "foundry_project_root", return_value=root), \
                 patch.object(lk, "cast_output", side_effect=fake_cast), \
                 patch.object(lk.walkthrough, "_receipt", side_effect=fake_receipt), \
                 patch.object(lk, "rpc_json", side_effect=fake_rpc_json), \
                 patch.object(lk.audit_context, "set_latest"), \
                 patch.object(lk.walkthrough, "_write_transaction_evidence"), \
                 patch.object(lk.audit_context, "emit"):
                result = lk.run_cast(
                    ["send", target, "--value", "0.01ether", "--rpc-url", explicit_rpc, "--yes"],
                    config,
                    capture=True,
                )

            self.assertEqual(result.code, 0)
            self.assertEqual(receipt_calls, [(explicit_rpc, tx_hash)])
            self.assertEqual(transaction_calls, [(explicit_rpc, "eth_getTransactionByHash")])


if __name__ == "__main__":
    unittest.main()
