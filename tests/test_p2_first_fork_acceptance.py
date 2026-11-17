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

    def test_default_archive_routes_are_proof_capable_and_avoid_publicnode(self):
        self.assertEqual(p2.DEFAULT_FORK_FALLBACK_RPC, "https://eth.drpc.org")
        self.assertNotIn("publicnode", p2.DEFAULT_FORK_FALLBACK_RPC)
        self.assertEqual(p2.DEFAULT_SOURCE_RPC, "https://rpc.mevblocker.io/fullprivacy")
        self.assertEqual(p2.DEFAULT_SOURCE_FALLBACK_RPC, "https://rpc.mevblocker.io/noreverts")
        self.assertEqual(p2.DEFAULT_SOURCE_ALT_RPC, "https://rpc.mevblocker.io/fast")

    def test_source_archive_tries_all_three_independent_historical_routes(self):
        first_error = RuntimeError("fullprivacy historical block lookup timed out")
        second_error = RuntimeError("noreverts historical code lookup failed")
        header = {"hash": "0x" + "5" * 64}
        proof = {"codeHash": "0x" + "6" * 64}
        responses = [
            "0x1", first_error,
            "0x1", second_error,
            "0x1", header, "0x6000", proof,
        ]
        with mock.patch.object(p2, "rpc", side_effect=responses) as request:
            active, attempts, evidence = p2.resolve_source_archive_provider(
                p2.DEFAULT_SOURCE_RPC,
                p2.DEFAULT_SOURCE_FALLBACK_RPC,
                p2.DEFAULT_FORK_UPSTREAM,
                123,
                alternate_rpc=p2.DEFAULT_SOURCE_ALT_RPC,
            )
        self.assertEqual(active, p2.DEFAULT_SOURCE_ALT_RPC)
        self.assertEqual(
            [item["status"] for item in attempts],
            ["unavailable", "unavailable", "selected"],
        )
        self.assertEqual(evidence["deployment_block_header"], header)
        self.assertEqual(evidence["deployment_code"], "0x6000")
        self.assertEqual(evidence["deployment_proof"], proof)
        self.assertEqual(request.call_count, 8)

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

    def test_source_archive_timeout_selects_independent_fallback(self):
        timeout = RuntimeError(
            "RPC eth_getBlockByNumber failed at rpc.mevblocker.io: "
            "TimeoutError: The read operation timed out"
        )
        header = {"hash": "0x" + "1" * 64}
        proof = {"codeHash": "0x" + "2" * 64}
        responses = [
            "0x1",          # primary chain ID is healthy
            timeout,        # but its historical deployment block times out
            "0x1",          # fallback chain ID
            header,         # fallback historical block
            "0x6000",       # fallback deployment code
            proof,          # fallback EIP-1186 proof
        ]
        with mock.patch.object(p2, "rpc", side_effect=responses) as request:
            active, attempts, evidence = p2.resolve_source_archive_provider(
                self.source,
                self.fallback,
                self.primary,
                123,
            )
        self.assertEqual(active, self.fallback)
        self.assertEqual([item["status"] for item in attempts], ["unavailable", "selected"])
        self.assertEqual(evidence["deployment_block_header"], header)
        self.assertEqual(evidence["deployment_code"], "0x6000")
        self.assertEqual(evidence["deployment_proof"], proof)
        self.assertEqual(request.call_count, 6)

    def test_source_archive_tries_independent_fork_fallback_if_first_source_fallback_fails(self):
        primary_timeout = RuntimeError("primary archive timed out")
        fallback_error = RuntimeError("fallback archive lacks historical state")
        header = {"hash": "0x" + "3" * 64}
        proof = {"codeHash": "0x" + "4" * 64}
        responses = [
            "0x1", primary_timeout,
            "0x1", fallback_error,
            "0x1", header, "0x6000", proof,
        ]
        alternate = "https://eth.llamarpc.com"
        with mock.patch.object(p2, "rpc", side_effect=responses) as request:
            active, attempts, evidence = p2.resolve_source_archive_provider(
                self.source,
                self.fallback,
                self.primary,
                123,
                alternate_rpc=alternate,
            )
        self.assertEqual(active, alternate)
        self.assertEqual([item["status"] for item in attempts], ["unavailable", "unavailable", "selected"])
        self.assertEqual(evidence["deployment_code"], "0x6000")
        self.assertEqual(request.call_count, 8)

    def test_source_archive_provider_never_reuses_fork_endpoint(self):
        with mock.patch.object(
            p2,
            "rpc",
            side_effect=RuntimeError("primary source timed out"),
        ):
            with self.assertRaisesRegex(RuntimeError, "No independent source/archive RPC"):
                p2.resolve_source_archive_provider(
                    self.source,
                    self.primary,
                    self.primary,
                    123,
                )

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
