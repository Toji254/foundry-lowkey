from __future__ import annotations

import unittest
from hardhat_deployment import parse_deploy_args, parse_probe_output, _transaction_evidence


class HardhatDeploymentParserTests(unittest.TestCase):
    def test_network_and_target_are_required(self):
        with self.assertRaisesRegex(ValueError, "--network is required"):
            parse_deploy_args(["scripts/Deploy.mjs", "--target", "Vault"])
        with self.assertRaisesRegex(ValueError, "--target is required"):
            parse_deploy_args(["scripts/Deploy.mjs", "--network", "localhost"])

    def test_duplicate_and_unknown_options_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "only once"):
            parse_deploy_args([
                "scripts/Deploy.mjs", "--network", "localhost",
                "--network", "dev", "--target", "Vault",
            ])
        with self.assertRaisesRegex(ValueError, "unsupported"):
            parse_deploy_args([
                "scripts/Deploy.mjs", "--network", "localhost",
                "--target", "Vault", "--rpc-url", "http://127.0.0.1:8545",
            ])

    def test_explicit_valid_selection(self):
        self.assertEqual(
            parse_deploy_args([
                "scripts/Deploy.mjs", "--network", "local-dev", "--target", "Vault"
            ]),
            ("scripts/Deploy.mjs", "local-dev", "Vault"),
        )

    def test_probe_output_requires_one_structured_context_record(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            parse_probe_output("no marker")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            parse_probe_output("LOWKEY_HARDHAT_CONTEXT={}\nLOWKEY_HARDHAT_CONTEXT={}\n")
        import json
        context = {
            "networkName": "localhost",
            "type": "http",
            "url": "http://127.0.0.1:18545",
            "accountsMode": "remote",
            "chainId": 31337,
            "chainIdLive": "0x7a69",
            "accountsLive": ["0x" + "11" * 20],
            "httpHeadersCount": 0,
            "environment": {},
        }
        parsed = parse_probe_output("LOWKEY_HARDHAT_CONTEXT=" + json.dumps(context) + "\n")
        self.assertEqual(parsed["networkName"], "localhost")


class HardhatTransactionEvidenceTests(unittest.TestCase):
    def _values(self, *, to=None, sender=None, status="0x1", latest="0x6000"):
        tx_hash = "0x" + "aa" * 32
        target = "0x" + "bb" * 20
        receipt = {
            "transactionHash": tx_hash,
            "status": status,
            "contractAddress": target,
            "blockNumber": "0x2",
            "blockHash": "0x" + "cc" * 32,
        }
        transaction = {
            "hash": tx_hash,
            "from": sender or "0x" + "11" * 20,
            "to": to,
        }
        block = {"hash": "0x" + "cc" * 32}
        calls = {"code": 0}
        def rpc(_url, method, _params):
            if method == "eth_getCode":
                calls["code"] += 1
                return "0x6000" if calls["code"] == 1 else latest
            return {
                "eth_getTransactionByHash": transaction,
                "eth_getTransactionReceipt": receipt,
                "eth_getBlockByNumber": block,
            }[method]
        return tx_hash, target, rpc

    def test_direct_creation_receipt_and_runtime_are_verified(self):
        tx_hash, target, rpc = self._values()
        lk = type("LK", (), {"rpc_json": staticmethod(rpc)})()
        evidence = _transaction_evidence(
            lk, "http://127.0.0.1:18545", "0x" + "11" * 20, tx_hash, target
        )
        self.assertEqual(evidence["target"], target)
        self.assertEqual(evidence["runtime_bytes"], 2)

    def test_factory_call_and_wrong_sender_are_blocked(self):
        tx_hash, target, rpc = self._values(to="0x" + "44" * 20)
        lk = type("LK", (), {"rpc_json": staticmethod(rpc)})()
        with self.assertRaisesRegex(ValueError, "direct contract-creation"):
            _transaction_evidence(
                lk, "http://127.0.0.1:18545", "0x" + "11" * 20, tx_hash, target
            )
        tx_hash, target, rpc = self._values(sender="0x" + "22" * 20)
        lk = type("LK", (), {"rpc_json": staticmethod(rpc)})()
        with self.assertRaisesRegex(ValueError, "sender"):
            _transaction_evidence(
                lk, "http://127.0.0.1:18545", "0x" + "11" * 20, tx_hash, target
            )

    def test_failed_receipt_and_changed_runtime_are_blocked(self):
        tx_hash, target, rpc = self._values(status="0x0")
        lk = type("LK", (), {"rpc_json": staticmethod(rpc)})()
        with self.assertRaisesRegex(ValueError, "did not report success"):
            _transaction_evidence(
                lk, "http://127.0.0.1:18545", "0x" + "11" * 20, tx_hash, target
            )
        tx_hash, target, rpc = self._values(latest="0x6001")
        lk = type("LK", (), {"rpc_json": staticmethod(rpc)})()
        with self.assertRaisesRegex(ValueError, "runtime changed"):
            _transaction_evidence(
                lk, "http://127.0.0.1:18545", "0x" + "11" * 20, tx_hash, target
            )


if __name__ == "__main__":
    unittest.main()
