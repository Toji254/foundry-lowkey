from __future__ import annotations

import unittest
from unittest import mock

from scripts import p2_first_fork_acceptance_e2e as p2


class P2RpcFallbackTests(unittest.TestCase):
    def test_rate_limited_primary_uses_independent_fallback_before_fork(self):
        snapshot = (123, {"hash": "0xabc"}, {"codeHash": "0xdef"}, "0x6000")
        with mock.patch.dict(
            p2.os.environ,
            {"LOWKEY_P2_FORK_FALLBACK_RPC_URL": "https://fallback.example"},
            clear=False,
        ), mock.patch.object(
            p2, "resolve_fork_snapshot",
            side_effect=[RuntimeError("HTTP Error 429: Too Many Requests"), snapshot],
        ) as resolver:
            selected = p2.resolve_fork_snapshot_with_fallback(
                "https://primary.example", "https://archive.example", 100
            )

        self.assertEqual(selected[0], "https://fallback.example")
        self.assertEqual(selected[1:5], snapshot)
        self.assertEqual(resolver.call_count, 2)
        self.assertEqual(
            [item["status"] for item in selected[5]],
            ["rate_limited", "selected_fallback"],
        )

    def test_non_rate_limit_failure_does_not_hide_a_real_rpc_error(self):
        with mock.patch.dict(
            p2.os.environ,
            {"LOWKEY_P2_FORK_FALLBACK_RPC_URL": "https://fallback.example"},
            clear=False,
        ), mock.patch.object(
            p2, "resolve_fork_snapshot",
            side_effect=RuntimeError("HTTP Error 503: upstream unavailable"),
        ) as resolver:
            with self.assertRaisesRegex(RuntimeError, "503"):
                p2.resolve_fork_snapshot_with_fallback(
                    "https://primary.example", "https://archive.example", 100
                )
        self.assertEqual(resolver.call_count, 1)

    def test_source_provider_is_not_reused_as_fork_fallback(self):
        with mock.patch.dict(
            p2.os.environ,
            {"LOWKEY_P2_FORK_FALLBACK_RPC_URL": "https://archive.example"},
            clear=False,
        ), mock.patch.object(
            p2, "resolve_fork_snapshot",
            side_effect=RuntimeError("HTTP Error 429: Too Many Requests"),
        ) as resolver:
            with self.assertRaisesRegex(RuntimeError, "rate-limited"):
                p2.resolve_fork_snapshot_with_fallback(
                    "https://primary.example", "https://archive.example", 100
                )
        self.assertEqual(resolver.call_count, 1)


if __name__ == "__main__":
    unittest.main()
