import json
import runpy
import unittest
from unittest.mock import Mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
P2 = runpy.run_path(str(ROOT / "scripts" / "p2-first-fork-acceptance-e2e.py"))

FORK_A = "https://fork-a.example/rpc"
FORK_B = "https://fork-b.example/rpc"
SOURCE = "https://source.example/archive"
BLOCK_HASH = "0x" + "a" * 64


class P2ForkRPCTests(unittest.TestCase):
    def test_endpoint_list_parses_comma_separated_values_and_deduplicates(self):
        values = P2["parse_endpoint_list"](
            f" {FORK_A}, {FORK_B}, {FORK_A} ",
            ("https://unused.example",),
        )
        self.assertEqual(values, [FORK_A, FORK_B])

    def test_endpoint_list_uses_defaults_when_override_is_blank(self):
        defaults = (FORK_A, FORK_B)
        self.assertEqual(P2["parse_endpoint_list"](" , ", defaults), list(defaults))

    def test_endpoint_list_rejects_non_http_urls(self):
        with self.assertRaisesRegex(AssertionError, "absolute HTTP"):
            P2["parse_endpoint_list"]("file:///tmp/rpc.json", ())

    def test_rpc_retries_json_rpc_429_responses_before_accepting_result(self):
        class Response:
            def __init__(self, payload):
                self.payload = payload
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, _limit):
                return json.dumps(self.payload).encode("utf-8")

        original_urlopen = P2["urlopen"]
        original_sleep = P2["time"].sleep
        responses = [
            Response({"jsonrpc": "2.0", "id": 1,
                      "error": {"code": 429, "message": "rate limited"}}),
            Response({"jsonrpc": "2.0", "id": 1, "result": "0x1"}),
        ]
        calls = []

        def fake_urlopen(request, timeout=25):
            calls.append((request.full_url, timeout))
            return responses.pop(0)

        P2["urlopen"] = fake_urlopen
        P2["time"].sleep = lambda _seconds: None
        try:
            result = P2["rpc"](FORK_A, "eth_chainId", [])
        finally:
            P2["urlopen"] = original_urlopen
            P2["time"].sleep = original_sleep

        self.assertEqual(result, "0x1")
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0], FORK_A)
        self.assertEqual(calls[1][0], FORK_A)

    def test_rpc_first_available_rotates_after_provider_error(self):
        original = P2["rpc"]
        calls = []

        def fake_rpc(url, method, params, timeout=25):
            calls.append(url)
            if url == FORK_A:
                raise RuntimeError("429 rate limited")
            return {"code": "0x1"}

        P2["rpc"] = fake_rpc
        try:
            result, endpoint = P2["rpc_first_available"](
                [FORK_A, FORK_B], "eth_getCode", ["0x" + "1" * 40, "0x10"]
            )
        finally:
            P2["rpc"] = original
        self.assertEqual(result, {"code": "0x1"})
        self.assertEqual(endpoint, FORK_B)
        self.assertEqual(calls, [FORK_A, FORK_B])

    def test_common_block_uses_any_matching_preflighted_fork_provider(self):
        original = P2["rpc"]

        def fake_rpc(url, method, params, timeout=25):
            if method == "eth_blockNumber":
                return {"https://fork-a.example/rpc": "0x63",
                        FORK_B: "0x62", SOURCE: "0x64"}[url]
            if method == "eth_getBlockByNumber":
                if url == FORK_A:
                    raise RuntimeError("429 rate limited")
                return {"hash": BLOCK_HASH, "number": params[0]}
            raise AssertionError(f"Unexpected RPC: {url} {method}")

        P2["rpc"] = fake_rpc
        try:
            block, header, endpoints = P2["pick_common_block"](
                [FORK_A, FORK_B], SOURCE
            )
        finally:
            P2["rpc"] = original
        self.assertEqual(block, 86)
        self.assertEqual(header["hash"], BLOCK_HASH)
        self.assertEqual(endpoints, [FORK_B])

    def test_anvil_command_uses_offline_chain_id_retry_and_provider_failover(self):
        argv = P2["build_anvil_fork_argv"](
            "/usr/bin/anvil", 8549, 20_000_086, [FORK_A, FORK_B]
        )
        self.assertIn("--fork-chain-id", argv)
        self.assertEqual(argv[argv.index("--fork-chain-id") + 1], "1")
        self.assertEqual(argv.count("--fork-url"), 2)
        self.assertIn("--retries", argv)
        self.assertEqual(argv[argv.index("--retries") + 1], "12")
        self.assertIn("--timeout", argv)
        self.assertEqual(argv[argv.index("--timeout") + 1], "120000")
        self.assertEqual(
            argv[argv.index("--fork-url") + 1],
            FORK_A,
        )
        second = argv.index("--fork-url", argv.index("--fork-url") + 1)
        self.assertEqual(argv[second + 1], FORK_B)

    def test_anvil_command_refuses_empty_provider_list(self):
        with self.assertRaisesRegex(ValueError, "At least one"):
            P2["build_anvil_fork_argv"]("/usr/bin/anvil", 8549, 20_000_086, [])


if __name__ == "__main__":
    unittest.main()
