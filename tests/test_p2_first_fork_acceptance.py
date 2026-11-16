"""Regression tests for P2 fork-provider failover."""
from __future__ import annotations

import importlib.util
import pathlib
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "p2-first-fork-acceptance-e2e.py"
SPEC = importlib.util.spec_from_file_location("lowkey_p2_acceptance", SCRIPT)
assert SPEC and SPEC.loader
p2 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p2)


class P2ForkFailoverTests(unittest.TestCase):
    def setUp(self):
        self.primary = "https://eth-mainnet.public.blastapi.io"
        self.fallback = "https://ethereum-rpc.publicnode.com"
        self.source = "https://rpc.mevblocker.io"
        self.snapshot = (123456, {"hash": "0xabc"}, {"codeHash": "0xdef"}, "0x6000")

    def test_chain_id_rate_limit_selects_independent_fallback(self):
        error = RuntimeError(
            "RPC eth_chainId failed at eth-mainnet.public.blastapi.io: "
            "HTTPError: HTTP Error 429: Too Many Requests"
        )
        with mock.patch.object(p2, "rpc", side_effect=[error, "0x1"]) as request:
            active, chain_id, attempts = p2.resolve_fork_upstream(
                self.primary, self.fallback, self.source
            )
        self.assertEqual(active, self.fallback)
        self.assertEqual(chain_id, 1)
        self.assertEqual([item["status"] for item in attempts], ["rate_limited", "selected_fallback"])
        self.assertEqual(request.call_count, 2)

    def test_chain_id_non_rate_limit_error_is_not_hidden_by_fallback(self):
        error = RuntimeError("RPC eth_chainId failed: connection refused")
        with mock.patch.object(p2, "rpc", side_effect=error) as request:
            with self.assertRaisesRegex(RuntimeError, "connection refused"):
                p2.resolve_fork_upstream(self.primary, self.fallback, self.source)
        request.assert_called_once()

    def test_historical_lookup_rate_limit_switches_to_fallback(self):
        error = RuntimeError(
            "RPC eth_getCode failed at eth-mainnet.public.blastapi.io: "
            "HTTPError: HTTP Error 429: Too Many Requests"
        )
        with (
            mock.patch.object(p2, "resolve_fork_snapshot", side_effect=[error, self.snapshot]) as resolve,
            mock.patch.object(p2, "rpc", return_value="0x1"),
        ):
            active, snapshot, attempts = p2.resolve_fork_snapshot_with_fallback(
                self.primary, self.fallback, self.source, 100
            )
        self.assertEqual(active, self.fallback)
        self.assertEqual(snapshot, self.snapshot)
        self.assertEqual([item["status"] for item in attempts], ["rate_limited", "selected_fallback"])
        self.assertEqual(resolve.call_count, 2)
        resolve.assert_any_call(self.fallback, self.source, 100)

    def test_source_archive_rate_limit_does_not_retry_wrong_provider(self):
        error = RuntimeError(
            "RPC eth_getProof failed at rpc.mevblocker.io: "
            "HTTPError: HTTP Error 429: Too Many Requests"
        )
        with mock.patch.object(p2, "resolve_fork_snapshot", side_effect=error) as resolve:
            with self.assertRaisesRegex(RuntimeError, "rpc.mevblocker.io"):
                p2.resolve_fork_snapshot_with_fallback(
                    self.primary, self.fallback, self.source, 100
                )
        resolve.assert_called_once_with(self.primary, self.source, 100)

    def test_snapshot_success_keeps_primary_provider(self):
        with mock.patch.object(p2, "resolve_fork_snapshot", return_value=self.snapshot) as resolve:
            active, snapshot, attempts = p2.resolve_fork_snapshot_with_fallback(
                self.primary, self.fallback, self.source, 100
            )
        self.assertEqual(active, self.primary)
        self.assertEqual(snapshot, self.snapshot)
        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0]["status"], "selected")
        resolve.assert_called_once_with(self.primary, self.source, 100)


if __name__ == "__main__":
    unittest.main()
