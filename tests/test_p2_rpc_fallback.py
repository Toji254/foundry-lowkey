from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
P2_SCRIPT = ROOT / "scripts" / "p2-first-fork-acceptance-e2e.py"
P2_SPEC = importlib.util.spec_from_file_location("p2_first_fork_acceptance_e2e", P2_SCRIPT)
if P2_SPEC is None or P2_SPEC.loader is None:
    raise ImportError(f"Cannot load P2 acceptance module from {P2_SCRIPT}")
p2 = importlib.util.module_from_spec(P2_SPEC)
sys.modules[P2_SPEC.name] = p2
P2_SPEC.loader.exec_module(p2)


class P2RpcFallbackTests(unittest.TestCase):
    def test_transient_primary_failure_selects_independent_fallback(self):
        with mock.patch.dict(
            p2.os.environ,
            {"LOWKEY_P2_FORK_FALLBACK_RPC_URL": "https://fallback.example"},
            clear=False,
        ), mock.patch.object(
            p2, "rpc", side_effect=[
                RuntimeError("HTTP Error 429: Too Many Requests"),
                "0x1",
            ],
        ) as rpc_call:
            provider, chain_id, attempts = p2.select_fork_provider(
                "https://primary.example", "https://source.example"
            )

        self.assertEqual(provider, "https://fallback.example")
        self.assertEqual(chain_id, 1)
        self.assertEqual(rpc_call.call_count, 2)
        self.assertEqual(
            [item["status"] for item in attempts],
            ["transient_failure", "selected_fallback"],
        )

    def test_non_transient_failure_is_not_hidden_by_fallback(self):
        with mock.patch.dict(
            p2.os.environ,
            {"LOWKEY_P2_FORK_FALLBACK_RPC_URL": "https://fallback.example"},
            clear=False,
        ), mock.patch.object(
            p2, "rpc", side_effect=RuntimeError("HTTP Error 401: unauthorized")
        ) as rpc_call:
            with self.assertRaisesRegex(RuntimeError, "401"):
                p2.select_fork_provider(
                    "https://primary.example", "https://source.example"
                )
        self.assertEqual(rpc_call.call_count, 1)

    def test_source_provider_is_never_reused_as_fork_fallback(self):
        with mock.patch.dict(
            p2.os.environ,
            {"LOWKEY_P2_FORK_FALLBACK_RPC_URL": "https://source.example"},
            clear=False,
        ), mock.patch.object(
            p2, "rpc", side_effect=RuntimeError("HTTP Error 429: Too Many Requests")
        ) as rpc_call:
            with self.assertRaisesRegex(AssertionError, "no independent fallback"):
                p2.select_fork_provider(
                    "https://primary.example", "https://source.example"
                )
        self.assertEqual(rpc_call.call_count, 1)


if __name__ == "__main__":
    unittest.main()
