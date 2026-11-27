"""Tests for receipt-backed deployment transaction provenance."""
from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("lowkey_deployment_receipt_evidence", ROOT / "lowkey" / "lk.py")
lk = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(lk)

RPC = "http://127.0.0.1:8545"
SENDER = "0x" + "11" * 20
TARGET = "0x" + "22" * 20
OTHER = "0x" + "33" * 20
TX = "0x" + "44" * 32


class DeploymentReceiptEvidenceTests(unittest.TestCase):
    def test_recovers_only_the_exact_successful_creation_receipt(self):
        calls = []

        def fake_rpc(_rpc, method, params):
            calls.append((method, params))
            if method == "eth_blockNumber":
                return "0x2"
            if method == "eth_getBlockByNumber":
                return {
                    "transactions": [
                        {"hash": "0x" + "55" * 32, "from": OTHER, "to": None},
                        {"hash": "0x" + "66" * 32, "from": SENDER, "to": TARGET},
                        {"hash": TX, "from": SENDER, "to": None},
                    ]
                }
            if method == "eth_getTransactionReceipt":
                assert params == [TX]
                return {"status": "0x1", "contractAddress": TARGET}
            raise AssertionError(method)

        with patch.object(lk, "rpc_json", side_effect=fake_rpc):
            recovered = lk._find_deployment_transaction_hash(
                RPC, SENDER, TARGET, starting_block="0x1"
            )

        self.assertEqual(recovered, TX)
        self.assertEqual(
            [method for method, _params in calls],
            ["eth_blockNumber", "eth_getBlockByNumber", "eth_getTransactionReceipt"],
        )

    def test_rejects_failed_receipt_and_wrong_created_address(self):
        def fake_rpc(_rpc, method, _params):
            if method == "eth_blockNumber":
                return "0x2"
            if method == "eth_getBlockByNumber":
                return {
                    "transactions": [
                        {"hash": TX, "from": SENDER, "to": None},
                    ]
                }
            if method == "eth_getTransactionReceipt":
                return {"status": "0x0", "contractAddress": OTHER}
            raise AssertionError(method)

        with patch.object(lk, "rpc_json", side_effect=fake_rpc):
            self.assertIsNone(
                lk._find_deployment_transaction_hash(
                    RPC, SENDER, TARGET, starting_block="0x1"
                )
            )

    def test_missing_or_malformed_block_data_remains_unavailable(self):
        with patch.object(lk, "rpc_json", return_value=None):
            self.assertIsNone(
                lk._find_deployment_transaction_hash(
                    RPC, SENDER, TARGET, starting_block="0x1"
                )
            )

    def test_deploy_artifact_recovers_hash_when_cast_omits_it(self):
        output = f"contractAddress: {TARGET}"
        calls = []

        def fake_rpc(_rpc, method, params):
            calls.append((method, params))
            if method == "eth_blockNumber":
                return "0x1" if len([m for m, _ in calls if m == "eth_blockNumber"]) == 1 else "0x2"
            if method == "eth_getBlockByNumber":
                return {
                    "transactions": [
                        {"hash": TX, "from": SENDER, "to": None},
                    ]
                }
            if method == "eth_getTransactionReceipt":
                return {"status": "0x1", "contractAddress": TARGET}
            raise AssertionError(method)

        with tempfile.TemporaryDirectory() as tmp:
            config = {}
            artifact = {
                "contractName": "ReceiptFixture",
                "abi": [],
                "bytecode": {"object": "0x6000"},
            }
            completed = SimpleNamespace(returncode=0, stdout=output, stderr="")
            with patch.object(lk.subprocess, "run", return_value=completed), \
                 patch.object(lk, "rpc_json", side_effect=fake_rpc), \
                 patch.object(lk, "cast_output", return_value=(0, "0x6000", "")):
                address, error = lk._deploy_artifact_locally(
                    config, pathlib.Path(tmp), RPC, [SENDER], artifact, [],
                    constructor_values=[], approved=True,
                )

        self.assertIsNone(error)
        self.assertEqual(address, TARGET)
        self.assertEqual(config["_last_deployment_receipt"]["tx_hash"], TX)
        self.assertEqual(
            config["_last_deployment_receipt"]["tx_hash_recovery_status"],
            "RECOVERED_FROM_CHAIN_RECEIPT",
        )


if __name__ == "__main__":
    unittest.main()
