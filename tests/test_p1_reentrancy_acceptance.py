from __future__ import annotations

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "p1-reentrancy-acceptance-e2e.py"
SPEC = importlib.util.spec_from_file_location("p1_reentrancy_acceptance_e2e", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
P1 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P1)


class TransactionEvidenceTests(unittest.TestCase):
    def test_reads_raw_rpc_value_and_receipt_gas(self):
        tx_hash = "0x" + "ab" * 32
        receipt = {
            "transactionHash": tx_hash,
            "status": "0x1",
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3b9aca00",
        }
        transaction = {
            "hash": tx_hash,
            "from": "0x" + "11" * 20,
            "to": "0x" + "22" * 20,
            "value": "0xde0b6b3a7640000",
        }
        responses = [
            subprocess.CompletedProcess([], 0, json.dumps(receipt), ""),
            subprocess.CompletedProcess([], 0, json.dumps(transaction), ""),
        ]

        with mock.patch.object(P1, "run", side_effect=responses) as run_mock:
            evidence = P1.transaction_evidence("cast", Path("/tmp"), {}, tx_hash)

        self.assertEqual(evidence["value_wei"], 10**18)
        self.assertEqual(evidence["gas_used"], 21000)
        self.assertEqual(evidence["effective_gas_price_wei"], 10**9)
        self.assertEqual(evidence["gas_cost_wei"], 21000 * 10**9)
        self.assertEqual(evidence["from_address"], transaction["from"])
        self.assertEqual(evidence["to_address"], transaction["to"])
        self.assertEqual(
            run_mock.call_args_list[1].args[0],
            ["cast", "rpc", "eth_getTransactionByHash", tx_hash, "--rpc-url", P1.RPC],
        )

    def test_missing_rpc_transaction_fails_closed(self):
        tx_hash = "0x" + "cd" * 32
        receipt = {
            "transactionHash": tx_hash,
            "status": "0x1",
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3b9aca00",
        }
        responses = [
            subprocess.CompletedProcess([], 0, json.dumps(receipt), ""),
            subprocess.CompletedProcess([], 0, "null", ""),
        ]

        with mock.patch.object(P1, "run", side_effect=responses):
            with self.assertRaisesRegex(AssertionError, "eth_getTransactionByHash"):
                P1.transaction_evidence("cast", Path("/tmp"), {}, tx_hash)


if __name__ == "__main__":
    unittest.main()
