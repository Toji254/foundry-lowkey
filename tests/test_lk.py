import importlib.util
import pathlib
import tempfile
from contextlib import redirect_stdout
import io
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "lk.py"

spec = importlib.util.spec_from_file_location("lowkeycast", MODULE)
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


class LowkeyCastTests(unittest.TestCase):
    def test_address_validation(self):
        self.assertTrue(lk.is_address("0x" + "1" * 40))
        self.assertFalse(lk.is_address("0x" + "1" * 64))
        self.assertFalse(lk.is_address(None))

    def test_tuple_canonicalization(self):
        self.assertEqual(
            lk.canonical_type({
                "type": "tuple",
                "components": [{"type": "address"}, {"type": "uint256"}],
            }),
            "(address,uint256)",
        )
        self.assertEqual(
            lk.canonical_type({
                "type": "tuple[]",
                "components": [{"type": "address"}, {"type": "uint256[]"}],
            }),
            "(address,uint256[])[]",
        )

    def test_output_signature(self):
        item = {
            "name": "quote",
            "inputs": [{"type": "address"}],
            "outputs": [{"type": "uint256"}, {"type": "bool"}],
        }
        self.assertEqual(
            lk.format_output_signature(item),
            "quote(address)(uint256,bool)",
        )

    def test_overload_matching(self):
        abi = [
            {"type": "function", "name": "foo", "inputs": [{"type": "uint256"}]},
            {"type": "function", "name": "foo", "inputs": [{"type": "address"}]},
        ]
        self.assertEqual(len(lk.matching_functions(abi, "foo")), 2)
        self.assertEqual(len(lk.matching_functions(abi, "foo(uint256)")), 1)

    def test_target_resolution(self):
        first = "0x" + "1" * 40
        second = "0x" + "2" * 40
        config = {
            "target": None,
            "aliases": {"alpha": first, "beta": second},
            "targets": {},
        }
        self.assertEqual(lk.resolve_target_ref(config, "alpha"), first)
        self.assertEqual(lk.resolve_target_ref(config, "1"), first)

    def test_secret_redaction(self):
        key = "0x" + "a" * 64
        redacted = lk.redact_secrets("--private-key " + key)
        self.assertIn("<redacted>", redacted)
        self.assertNotIn(key, redacted)
        self.assertIn("<redacted>", lk.redact_secrets("--jwt-secret supersecret"))

    def test_rpc_redaction(self):
        value = lk.redact_secrets("--rpc-url https://example.com/sensitive-token")
        self.assertNotIn("sensitive-token", value)
        self.assertIn("<redacted>", value)

    def test_eth_humanization(self):
        self.assertIn("1.0000 ETH", lk.humanize_value("1000000000000000000"))

    def test_private_key_normalization(self):
        raw = "b" * 64
        self.assertEqual(lk.normalize_private_key(raw), "0x" + raw)
        self.assertIsNone(lk.normalize_private_key("bad-key"))

    def test_runtime_fixes(self):
        self.assertTrue(hasattr(lk, "Path"))
        self.assertTrue(lk.AUDIT_CHECKLIST)

    def test_receipt_uses_async(self):
        tx_hash = "0x" + "1" * 64
        config = {"last_tx": tx_hash}
        with patch.object(lk, "run_cast") as run_cast:
            lk.run_receipt(config)
            run_cast.assert_called_once_with(["receipt", tx_hash, "--async"], config)

    def test_scan_smoke(self):
        source = "contract X { function f() external { (bool ok,) = msg.sender.call{value: 1}(\"\"); require(ok); } function g() external { address a = tx.origin; } }"
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "X.sol"
            path.write_text(source, encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                lk.run_scan([tmp])
            self.assertIn("REENTRANCY REVIEW", output.getvalue())
            self.assertIn("TX.ORIGIN", output.getvalue())

    def test_event_command_does_not_use_topics_flag(self):
        with patch.object(lk, "cast_output", return_value=(0, "decoded", "")) as cast_output:
            result = lk.run_event({}, ["Transfer(address,address,uint256)", "0x", "0x1"])
            self.assertEqual(result, 0)
            cast_output.assert_called_once_with([
                "cast", "decode-event", "--sig",
                "Transfer(address,address,uint256)", "0x", "0x1"
            ])

    def test_solidity_identifier(self):
        self.assertEqual(
            lk.solidity_identifier("unauthorized release #1"),
            "unauthorized_release__1",
        )

if __name__ == "__main__":
    unittest.main()
