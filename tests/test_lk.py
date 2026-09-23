import importlib.util
import json
import os
import pathlib
import subprocess
import sys
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
    def run_cli(self, *args):
        with tempfile.TemporaryDirectory() as home:
            env = os.environ.copy()
            env["HOME"] = home
            return subprocess.run(
                [sys.executable, str(MODULE), *args],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )

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

    def test_findings_command_is_handled_by_lowkey(self):
        result = self.run_cli("findings")
        self.assertNotIn("unrecognized subcommand 'findings'", result.stderr)
        self.assertIn("LOWKEY FINDINGS", result.stdout)

    def test_focus_command_is_handled_by_lowkey(self):
        result = self.run_cli("focus")
        self.assertNotIn("unrecognized subcommand 'focus'", result.stderr)
        self.assertIn("Set target first.", result.stderr)

    def test_audit_checks_flag_is_dispatched(self):
        result = self.run_cli("audit", "--checks")
        self.assertNotIn("unrecognized subcommand 'checks'", result.stderr)

    def test_audit_compact_checks_alias_is_dispatched(self):
        result = self.run_cli("audit--checks")
        self.assertNotIn("unrecognized subcommand 'audit--checks'", result.stderr)

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
            result = lk.run_event({}, ["Transfer(address,address,uint256)", "0x", "0x01"])
            self.assertEqual(result, 0)
            cast_output.assert_called_once_with([
                "cast", "decode-event", "--sig",
                "Transfer(address,address,uint256)", "0x01"
            ])

    def test_event_failure_returns_nonzero(self):
        with patch.object(lk, "cast_output", return_value=(1, "", "decode failed")):
            self.assertEqual(lk.run_event({}, ["Transfer(address,address,uint256)", "0xdeadbeef"]), 1)

    def test_cli_successful_event(self):
        result = self.run_cli(
            "event",
            "Ping(uint256)",
            "0x000000000000000000000000000000000000000000000000000000000000002a",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("42", result.stdout)

    def test_indexed_event_decoding_uses_abi_topics(self):
        event = {
            "type": "event",
            "name": "Transfer",
            "inputs": [
                {"name": "from", "type": "address", "indexed": True},
                {"name": "to", "type": "address", "indexed": True},
                {"name": "amount", "type": "uint256", "indexed": False},
            ],
        }
        topic0 = "0x" + "a" * 64
        topics = [topic0, "0x" + "0" * 24 + "1" * 40, "0x" + "0" * 24 + "2" * 40]

        def cast_result(args, input_text=None):
            if args[1] == "sig-event":
                return 0, topic0, ""
            return 0, "42", ""

        with tempfile.TemporaryDirectory() as tmp:
            abi_path = pathlib.Path(tmp) / "abi.json"
            abi_path.write_text(json.dumps({"abi": [event]}), encoding="utf-8")
            output = io.StringIO()
            with patch.object(lk, "cast_output", side_effect=cast_result):
                with redirect_stdout(output):
                    result = lk.run_event(
                        {"target": "target", "abi_paths": {"target": str(abi_path)}},
                        ["Transfer(address,address,uint256)", "0x" , *topics],
                    )
        self.assertEqual(result, 0)
        self.assertIn("Indexed from", output.getvalue())
        self.assertIn("Data: 42", output.getvalue())

    def test_cli_failure_exit_codes(self):
        cases = [
            ("event", "Transfer(address,address,uint256)", "0xdeadbeef", "0x1"),
            ("target", "not-an-address"),
            ("receipt", "not-a-hash"),
            ("scan", "/path/does/not/exist"),
            ("definitely-not-a-command",),
            ("raw", "definitely-not-a-cast-command"),
            ("receipt", "0x" + "0" * 64),
        ]
        for args in cases:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_scan_regression_markers(self):
        source = """
        contract Regression {
            function f(address target) external payable {
                target.call{value: 1 ether}(\"\");
                target.delegatecall(\"\");
                address caller = tx.origin;
            }
        }
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "Regression.sol"
            path.write_text(source, encoding="utf-8")
            result = self.run_cli("scan", tmp)
            single_file_result = self.run_cli("scan", str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(single_file_result.returncode, 0, single_file_result.stderr)
        self.assertIn("REENTRANCY REVIEW", result.stdout)
        self.assertIn("DELEGATECALL", result.stdout)
        self.assertIn("TX.ORIGIN", result.stdout)
        self.assertIn("REENTRANCY REVIEW", single_file_result.stdout)
        self.assertIn("DELEGATECALL", single_file_result.stdout)
        self.assertIn("TX.ORIGIN", single_file_result.stdout)

    def test_runtime_sync_detects_stale_source_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = pathlib.Path(tmp) / "install-manifest.json"
            installed = pathlib.Path(tmp) / "lk.py"
            installed.write_text("installed", encoding="utf-8")
            digest = lk._sha256_file(str(installed))
            manifest_path.write_text(
                json.dumps(
                    {
                        "git_sha": "old-" + "0" * 8,
                        "source_repo": str(ROOT),
                        "files": {str(installed): digest},
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(lk, "INSTALL_MANIFEST", str(manifest_path)):
                status = lk.runtime_sync_status()
        self.assertEqual(status["status"], "stale")
        self.assertIn("source checkout is", status["detail"])

    def test_version_reports_runtime_state(self):
        with patch.object(
            lk,
            "runtime_sync_status",
            return_value={"status": "ok", "detail": "installed runtime abc123"},
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                lk.run_version()
        rendered = output.getvalue()
        self.assertIn("LowkeyCast 2.1", rendered)
        self.assertIn("Runtime: OK", rendered)
        self.assertIn("installed runtime abc123", rendered)

    def test_doctor_reports_missing_dependencies(self):
        with patch.object(lk.shutil, "which", return_value=None):
            self.assertEqual(lk.run_doctor(), 1)

    def test_solidity_identifier(self):
        self.assertEqual(
            lk.solidity_identifier("unauthorized release #1"),
            "unauthorized_release__1",
        )

if __name__ == "__main__":
    unittest.main()
