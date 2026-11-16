from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "p2-first-fork-acceptance-e2e.py"
SPEC = importlib.util.spec_from_file_location("p2_first_fork_acceptance", SCRIPT)
p2 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = p2
SPEC.loader.exec_module(p2)


class P2ProviderSelectionTests(unittest.TestCase):
    def test_fork_provider_falls_back_after_transient_primary_rate_limit(self):
        primary = "https://primary-fork.example"
        fallback = "https://fallback-fork.example"
        source = "https://archive-source.example"

        def fake_rpc(url, method, params, timeout=25):
            self.assertEqual(method, "eth_chainId")
            if url == primary:
                raise RuntimeError("HTTP Error 429: Too Many Requests")
            if url == fallback:
                return "0x1"
            raise AssertionError("unexpected provider: " + url)

        with patch.dict(os.environ, {"LOWKEY_P2_FORK_FALLBACK_RPC_URL": fallback}):
            with patch.object(p2, "rpc", side_effect=fake_rpc):
                selected, chain_id, attempts = p2.select_fork_provider(primary, source)

        self.assertEqual(selected, fallback)
        self.assertEqual(chain_id, 1)
        self.assertEqual(
            [row["status"] for row in attempts],
            ["transient_failure", "selected_fallback"],
        )
        self.assertNotEqual(attempts[0]["provider"], attempts[1]["provider"])

    def test_source_provider_falls_back_to_independent_archive_with_eip1186(self):
        primary = "https://primary-source.example"
        fallback = "https://fallback-archive.example"
        fork = "https://fork-provider.example"
        pinned_snapshot = (123, {"hash": "0xabc"}, {"codeHash": "0xdef"}, "0x6000")

        def fake_rpc(url, method, params, timeout=25):
            if method == "eth_chainId":
                return "0x1"
            if method == "eth_getBlockByNumber":
                return {"hash": "0xdeployment"}
            if method == "eth_getCode":
                return "0x6000"
            raise AssertionError("unexpected RPC method: " + method)

        with patch.dict(os.environ, {"LOWKEY_P2_SOURCE_FALLBACK_RPC_URL": fallback}):
            with patch.object(p2, "rpc", side_effect=fake_rpc):
                with patch.object(
                    p2,
                    "resolve_fork_snapshot",
                    side_effect=[RuntimeError("The read operation timed out"), pinned_snapshot],
                ):
                    selected, chain_id, snapshot, attempts = p2.select_source_provider(
                        primary, fork, 100
                    )

        self.assertEqual(selected, fallback)
        self.assertEqual(chain_id, 1)
        self.assertEqual(snapshot, pinned_snapshot)
        self.assertEqual([row["status"] for row in attempts], ["rejected", "selected"])
        self.assertNotEqual(attempts[-1]["provider"], p2.urlparse_safe(fork))

    def test_source_provider_never_reuses_fork_endpoint(self):
        fork = "https://same-provider.example"

        def fake_rpc(url, method, params, timeout=25):
            self.assertNotEqual(p2.urlparse_safe(url), p2.urlparse_safe(fork))
            if method == "eth_chainId":
                return "0x1"
            if method == "eth_getBlockByNumber":
                return {"hash": "0xdeployment"}
            if method == "eth_getCode":
                return "0x6000"
            raise AssertionError("unexpected method")

        with patch.dict(os.environ, {"LOWKEY_P2_SOURCE_FALLBACK_RPC_URL": ""}):
            with patch.object(p2, "rpc", side_effect=fake_rpc):
                with patch.object(p2, "resolve_fork_snapshot", return_value=(123, {"hash": "0xabc"}, {"codeHash": "0xdef"}, "0x6000")):
                    selected, chain_id, snapshot, attempts = p2.select_source_provider(
                        fork, fork, 100
                    )

        self.assertNotEqual(p2.urlparse_safe(selected), p2.urlparse_safe(fork))
        self.assertEqual(chain_id, 1)


if __name__ == "__main__":
    unittest.main()
