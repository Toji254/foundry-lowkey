import importlib.util
import io
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "block_tools.py"

spec = importlib.util.spec_from_file_location("lowkey_block_tools", MODULE)
block_tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(block_tools)
_UNSET = object()


class BlockToolsTests(unittest.TestCase):
    def setUp(self):
        self.block = {
            "number": "0x5",
            "hash": "0x" + "a" * 64,
            "parentHash": "0x" + "b" * 64,
            "timestamp": "0x654321",
            "miner": "0x" + "1" * 40,
            "gasUsed": "0x5208",
            "gasLimit": "0x1c9c380",
            "baseFeePerGas": "0x3b9aca00",
            "transactions": ["0x" + "c" * 64],
        }

    def run_cli(self, args, block=_UNSET):
        stdout = io.StringIO()
        stderr = io.StringIO()
        result_block = self.block if block is _UNSET else block
        with patch.object(block_tools, "resolve_rpc", return_value="http://127.0.0.1:8545"), \
             patch.object(block_tools, "rpc_request", return_value=result_block) as rpc, \
             redirect_stdout(stdout), redirect_stderr(stderr):
            code = block_tools.main(args)
        return code, stdout.getvalue(), stderr.getvalue(), rpc

    def test_decimal_block_reference_becomes_rpc_quantity(self):
        self.assertEqual(block_tools.parse_block_reference("5"), "0x5")
        self.assertEqual(block_tools.parse_block_reference("0005"), "0x5")

    def test_hex_block_reference_is_canonicalized(self):
        self.assertEqual(block_tools.parse_block_reference("0x0005"), "0x5")
        self.assertEqual(block_tools.parse_block_reference("0X05"), "0x5")

    def test_standard_block_tags_are_preserved(self):
        for tag in ("latest", "earliest", "pending", "safe", "finalized"):
            with self.subTest(tag=tag):
                self.assertEqual(block_tools.parse_block_reference(tag), tag)

    def test_invalid_block_reference_is_rejected(self):
        for reference in ("-1", "0x", "latestest", "5.2", "abc"):
            with self.subTest(reference=reference):
                with self.assertRaises(block_tools.BlockLookupError):
                    block_tools.parse_block_reference(reference)

    def test_hash_subcommand_reads_block_hash_only(self):
        code, stdout, stderr, rpc = self.run_cli(["hash", "5"])
        self.assertEqual(code, 0, stderr)
        self.assertEqual(stdout.strip(), self.block["hash"])
        rpc.assert_called_once_with(
            "http://127.0.0.1:8545",
            "eth_getBlockByNumber",
            ["0x5", False],
        )

    def test_hash_flag_reads_block_hash_only(self):
        code, stdout, stderr, rpc = self.run_cli(["0x5", "--hash"])
        self.assertEqual(code, 0, stderr)
        self.assertEqual(stdout.strip(), self.block["hash"])
        rpc.assert_called_once_with(
            "http://127.0.0.1:8545",
            "eth_getBlockByNumber",
            ["0x5", False],
        )

    def test_full_block_view_contains_header_and_numeric_fields(self):
        code, stdout, stderr, rpc = self.run_cli(["5"])
        self.assertEqual(code, 0, stderr)
        self.assertIn("BLOCK 5", stdout)
        self.assertIn(f"Hash:            {self.block['hash']}", stdout)
        self.assertIn(f"Parent hash:     {self.block['parentHash']}", stdout)
        self.assertIn("Timestamp:       6636321 (", stdout)
        self.assertIn("Gas used:        21000", stdout)
        self.assertIn("Transactions:    1", stdout)
        rpc.assert_called_once_with(
            "http://127.0.0.1:8545",
            "eth_getBlockByNumber",
            ["0x5", False],
        )

    def test_json_mode_returns_the_raw_block_object(self):
        code, stdout, stderr, _ = self.run_cli(["5", "--json"])
        self.assertEqual(code, 0, stderr)
        self.assertEqual(json.loads(stdout), self.block)

    def test_null_block_is_reported_as_not_found(self):
        code, stdout, stderr, _ = self.run_cli(["999"], block=None)
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("was not found", stderr)

    def test_pending_block_without_hash_is_not_misrepresented(self):
        pending = dict(self.block, number=None, hash=None)
        code, stdout, stderr, _ = self.run_cli(["hash", "pending"], block=pending)
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("no finalized hash", stderr)

    def test_invalid_rpc_url_is_rejected(self):
        with self.assertRaises(block_tools.BlockLookupError):
            block_tools.resolve_rpc("file:///tmp/not-an-rpc")

    def test_explicit_rpc_url_takes_priority(self):
        self.assertEqual(
            block_tools.resolve_rpc("https://rpc.example"),
            "https://rpc.example",
        )

    def test_help_is_available_without_an_rpc(self):
        output = io.StringIO()
        with redirect_stdout(output), patch.object(
            block_tools, "resolve_rpc", side_effect=AssertionError("help must not connect")
        ):
            code = block_tools.main(["--h"])
        self.assertEqual(code, 0)
        self.assertIn("lk block hash <number|tag>", output.getvalue())
        self.assertIn("eth_getBlockByNumber", output.getvalue())

    def test_launcher_routes_block_to_installed_module_before_generic_help(self):
        script = (ROOT / "bin" / "lk").read_text(encoding="utf-8")
        self.assertIn('if [[ "${1:-}" == "block" || "${1:-}" == "blocks" ]]', script)
        self.assertIn('python3 "$HOME/.lowkey/block_tools.py" "$@"', script)

        with tempfile.TemporaryDirectory() as tmp:
            lowkey_dir = pathlib.Path(tmp) / ".lowkey"
            lowkey_dir.mkdir()
            module = lowkey_dir / "block_tools.py"
            module.write_text(
                "import json, sys\\nprint(json.dumps(sys.argv[1:]))\\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["HOME"] = tmp
            result = subprocess.run(
                ["bash", str(ROOT / "bin" / "lk"), "block", "hash", "5"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), ["hash", "5"])

    def test_installer_stages_compiles_installs_and_hashes_block_module(self):
        script = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn("finding_explainer.py block_tools.py; do", script)
        self.assertIn('"$STAGE_DIR/block_tools.py"', script)
        self.assertIn('cp "$STAGE_DIR/block_tools.py" "$TARGET_LOWKEY_DIR/block_tools.py"', script)
        self.assertIn('str(lowkey_dir / "block_tools.py"): sha256(lowkey_dir / "block_tools.py")', script)
        self.assertIn('- $TARGET_LOWKEY_DIR/block_tools.py', script)


if __name__ == "__main__":
    unittest.main()
