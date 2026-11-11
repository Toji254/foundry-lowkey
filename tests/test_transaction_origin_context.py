import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "lk.py"
spec = importlib.util.spec_from_file_location("lowkeycast_tx_origin_context", MODULE)
lk = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(lk)


class TransactionOriginContextTests(unittest.TestCase):
    def setUp(self):
        self.origin = "0x" + "1" * 40
        self.attacker = "0x" + "2" * 40
        self.target = "0x" + "3" * 40
        self.tx_hash = "0x" + "a" * 64

    def test_nested_call_reports_intermediary_as_target_msg_sender(self):
        trace = {
            "type": "CALL",
            "from": self.origin,
            "to": self.attacker,
            "calls": [
                {
                    "type": "CALL",
                    "from": self.attacker,
                    "to": self.target,
                    "calls": [],
                }
            ],
        }
        self.assertEqual(
            lk._trace_target_msg_senders(trace, self.target, self.origin),
            [(self.attacker, "CALL")],
        )

    def test_delegatecall_preserves_parent_msg_sender(self):
        implementation = "0x" + "4" * 40
        proxy_trace = {
            "type": "CALL",
            "from": self.origin,
            "to": self.attacker,
            "calls": [
                {
                    "type": "DELEGATECALL",
                    "from": self.attacker,
                    "to": implementation,
                    "calls": [],
                }
            ],
        }
        self.assertEqual(
            lk._trace_target_msg_senders(proxy_trace, implementation, self.origin),
            [(self.origin, "DELEGATECALL")],
        )

    def test_call_after_delegatecall_uses_proxy_execution_context(self):
        implementation = "0x" + "4" * 40
        trace = {
            "type": "CALL",
            "from": self.origin,
            "to": self.attacker,
            "calls": [
                {
                    "type": "DELEGATECALL",
                    "from": self.attacker,
                    "to": implementation,
                    "calls": [
                        {
                            "type": "CALL",
                            "to": self.target,
                            "calls": [],
                        }
                    ],
                }
            ],
        }
        self.assertEqual(
            lk._trace_target_msg_senders(trace, self.target, self.origin),
            [(self.attacker, "CALL")],
        )

    def test_call_trace_without_matching_target_does_not_guess_sender(self):
        trace = {
            "type": "CALL",
            "from": self.origin,
            "to": self.attacker,
            "calls": [],
        }
        self.assertEqual(
            lk._trace_target_msg_senders(trace, self.target, self.origin),
            [],
        )

    def test_direct_transaction_labels_origin_and_target_msg_sender(self):
        tx = {
            "hash": self.tx_hash,
            "from": self.origin,
            "to": self.target,
            "value": "0x0",
            "blockNumber": "0xa",
            "input": "0x",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            output = io.StringIO()
            config = {
                "target": self.target,
                "target_contract": "Telephone",
                "actor": "Alice",
                "wallets": {},
                "labels": {},
            }
            with patch.object(lk, "cast_output", return_value=(0, json.dumps(tx), "")), \
                 patch.object(lk, "effective_rpc", return_value="http://127.0.0.1:8545"), \
                 patch.object(lk, "project_context_target", return_value={"address": self.target, "contract": "Telephone"}), \
                 patch.object(lk, "active_project_target", return_value=self.target), \
                 patch.object(lk.walkthrough, "_receipt", return_value=None), \
                 patch.object(lk.walkthrough, "_write_transaction_evidence"), \
                 patch.object(lk.walkthrough, "_transaction_link", return_value=self.tx_hash), \
                 patch.object(lk, "load_abi", return_value=[]), \
                 patch.object(lk.audit_context, "foundry_project_root", return_value=pathlib.Path(temp_dir)), \
                 redirect_stdout(output):
                code = lk.run_tx(config, [self.tx_hash])

        rendered = output.getvalue()
        self.assertIn("tx.origin:", rendered)
        self.assertIn(self.origin, rendered)
        self.assertIn("msg.sender at Telephone (direct):", rendered)

    def test_transaction_value_is_shown_in_eth_and_wei(self):
        tx = {
            "hash": self.tx_hash,
            "from": self.origin,
            "to": self.target,
            "value": hex(10**18),
            "blockNumber": "0xa",
            "input": "0x",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            output = io.StringIO()
            config = {
                "target": self.target,
                "target_contract": "Telephone",
                "actor": "Alice",
                "wallets": {},
                "labels": {},
            }
            with patch.object(lk, "cast_output", return_value=(0, json.dumps(tx), "")), \
                 patch.object(lk, "effective_rpc", return_value="http://127.0.0.1:8545"), \
                 patch.object(lk.walkthrough, "_receipt", return_value=None), \
                 patch.object(lk.walkthrough, "_write_transaction_evidence"), \
                 patch.object(lk.walkthrough, "_transaction_link", return_value=self.tx_hash), \
                 patch.object(lk, "load_abi", return_value=[]), \
                 patch.object(lk.audit_context, "foundry_project_root", return_value=pathlib.Path(temp_dir)), \
                 redirect_stdout(output):
                lk.run_tx(config, [self.tx_hash])

        rendered = output.getvalue()
        self.assertIn("ETH value: 1 ETH (1,000,000,000,000,000,000 wei)", rendered)
        self.assertIn("native ETH attached to the top-level transaction", rendered)


    def test_intermediary_transaction_uses_call_trace_for_target_sender(self):
        tx = {
            "hash": self.tx_hash,
            "from": self.origin,
            "to": self.attacker,
            "value": "0x0",
            "blockNumber": "0xa",
            "input": "0x",
        }
        trace = {
            "type": "CALL",
            "from": self.origin,
            "to": self.attacker,
            "calls": [
                {
                    "type": "CALL",
                    "from": self.attacker,
                    "to": self.target,
                    "calls": [],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            output = io.StringIO()
            config = {
                "target": self.target,
                "target_contract": "Telephone",
                "actor": "Alice",
                "wallets": {},
                "labels": {},
            }
            with patch.object(lk, "cast_output", return_value=(0, json.dumps(tx), "")), \
                 patch.object(lk, "effective_rpc", return_value="http://127.0.0.1:8545"), \
                 patch.object(lk, "project_context_target", return_value={"address": self.target, "contract": "Telephone"}), \
                 patch.object(lk, "active_project_target", return_value=self.target), \
                 patch.object(lk, "rpc_json", return_value=trace) as rpc_call, \
                 patch.object(lk.walkthrough, "_receipt", return_value=None), \
                 patch.object(lk.walkthrough, "_write_transaction_evidence"), \
                 patch.object(lk.walkthrough, "_transaction_link", return_value=self.tx_hash), \
                 patch.object(lk, "load_abi", return_value=[]), \
                 patch.object(lk.audit_context, "foundry_project_root", return_value=pathlib.Path(temp_dir)), \
                 redirect_stdout(output):
                code = lk.run_tx(config, [self.tx_hash])

        rendered = output.getvalue()
        self.assertIn(f"tx.origin: {self.origin}", rendered)
        self.assertIn(f"msg.sender at Telephone (CALL): {self.attacker}", rendered)
        rpc_call.assert_called_once_with(
            "http://127.0.0.1:8545",
            "debug_traceTransaction",
            [self.tx_hash, {"tracer": "callTracer"}],
        )


    def test_pending_transaction_does_not_claim_evaluated_context(self):
        tx = {
            "hash": self.tx_hash,
            "from": self.origin,
            "to": self.target,
            "value": "0x0",
            "input": "0x",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            output = io.StringIO()
            config = {
                "target": self.target,
                "target_contract": "Telephone",
                "actor": "Alice",
                "wallets": {},
                "labels": {},
            }
            with patch.object(lk, "cast_output", return_value=(0, json.dumps(tx), "")), \
                 patch.object(lk, "effective_rpc", return_value="http://127.0.0.1:8545"), \
                 patch.object(lk, "rpc_json") as rpc_call, \
                 patch.object(lk.walkthrough, "_receipt", return_value=None), \
                 patch.object(lk.walkthrough, "_write_transaction_evidence"), \
                 patch.object(lk.walkthrough, "_transaction_link", return_value=self.tx_hash), \
                 patch.object(lk, "load_abi", return_value=[]), \
                 patch.object(lk.audit_context, "foundry_project_root", return_value=pathlib.Path(temp_dir)), \
                 redirect_stdout(output):
                lk.run_tx(config, [self.tx_hash])

        rendered = output.getvalue()
        self.assertIn(f"Expected tx.origin when mined: {self.origin}", rendered)
        self.assertIn("msg.sender context: unavailable until the transaction is mined", rendered)
        rpc_call.assert_not_called()

if __name__ == "__main__":
    unittest.main()
