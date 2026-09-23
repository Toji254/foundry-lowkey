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
        self.assertIn("1.0000 ETH", lk.humanize_value("1000000000000000000", assume_wei=True))

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
            result = lk.run_event({}, ["Transfer(address,address,uint256)", "0x", "0x01"])
            self.assertEqual(result, 0)
            cast_output.assert_called_once_with([
                "cast", "decode-event", "--sig",
                "Transfer(address,address,uint256)", "0x01"
            ])

    def test_event_failure_returns_nonzero(self):
        with patch.object(lk, "cast_output", return_value=(1, "", "decode failed")):
            self.assertEqual(lk.run_event({}, ["Transfer(address,address,uint256)", "0xdeadbeef"]), 1)

    def test_event_success(self):
        output=io.StringIO()
        with patch.object(lk, "cast_output", return_value=(0, "42", "")):
            with redirect_stdout(output):
                result=lk.run_event(
                    {},
                    [
                        "Ping(uint256)",
                        "0x000000000000000000000000000000000000000000000000000000000000002a",
                    ],
                )
        self.assertEqual(result, 0)
        self.assertIn("42", output.getvalue())

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

    def test_anvil_detection(self):
        address = "0x" + "1" * 40
        with patch.object(lk, "local_port_open", return_value=True):
            with patch.object(
                lk,
                "rpc_json",
                side_effect=["anvil/v1.8.1", [address]],
            ):
                info = lk.detect_anvil_rpc(None)
        self.assertEqual(info["url"], "http://127.0.0.1:8545")
        self.assertEqual(info["accounts"], [address])

    def test_effective_rpc_auto_detects_anvil(self):
        address="0x"+"1"*40
        info={"url":"http://127.0.0.1:8545","client":"anvil/v1.8.1","accounts":[address]}
        config={"rpc":None}
        with patch.object(lk, "detect_anvil_rpc", return_value=info):
            self.assertEqual(lk.effective_rpc(config), "http://127.0.0.1:8545")
            self.assertEqual(config["_auto_rpc_info"], info)

    def test_default_anvil_actor_selection_and_unique_assignment(self):
        address = "0x" + "1" * 40
        config = {"wallets": {}, "actor": None}
        info = {"url": "http://127.0.0.1:8545", "accounts": [address]}
        with patch.object(lk, "detect_anvil_rpc", return_value=info), \
             patch.object(lk, "derive_default_anvil_key", return_value="0x" + "a" * 64), \
             patch.object(lk, "cast_output", return_value=(0, address, "")), \
             patch.object(lk, "save_config"):
            self.assertEqual(lk.select_anvil_actor(config, 0, "Alice"), 0)
            self.assertEqual(config["actor"], "Alice")
            self.assertEqual(config["wallets"]["Alice"]["anvil_index"], 0)
            self.assertEqual(lk.select_anvil_actor(config, 0, "Bob"), 2)

    def test_anvil_actor_key_is_not_stored(self):
        address="0x"+"1"*40
        config={
            "wallets":{
                "Alice":{
                    "source":"anvil-default",
                    "anvil_index":0,
                    "address":address,
                }
            },
            "actor":"Alice",
        }
        info={"url":"http://127.0.0.1:8545","accounts":[address]}
        with patch.object(lk, "anvil_rpc_info", return_value=info), \
             patch.object(lk, "derive_default_anvil_key", return_value="0x"+"b"*64), \
             patch.object(lk, "cast_output", return_value=(0, address, "")):
            self.assertEqual(lk.resolve_wallet_key(config), "0x"+"b"*64)
        self.assertNotIn("private_key", config["wallets"]["Alice"])

    def test_anvil_actor_rejects_custom_account_for_default_key(self):
        recorded="0x"+"1"*40
        actual="0x"+"2"*40
        config={
            "wallets":{
                "Alice":{
                    "source":"anvil-default",
                    "anvil_index":0,
                    "address":recorded,
                }
            },
            "actor":"Alice",
        }
        info={"url":"http://127.0.0.1:8545","accounts":[actual]}
        with patch.object(lk, "anvil_rpc_info", return_value=info):
            self.assertIsNone(lk.resolve_wallet_key(config))

    def test_load_abi_auto_from_local_artifact(self):
        artifact = {
            "contractName": "Escrow",
            "abi": [
                {
                    "type": "function",
                    "name": "release",
                    "inputs": [],
                    "stateMutability": "nonpayable",
                }
            ],
            "storageLayout": {"storage": []},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "Escrow.json"
            path.write_text(json.dumps(artifact), encoding="utf-8")
            with patch.object(lk, "local_artifact_paths", return_value=[str(path)]):
                config = {"target_contract": "Escrow", "abi_paths": {}}
                abi = lk.load_abi("0x" + "1" * 40, config)
        self.assertEqual(abi[0]["name"], "release")
        self.assertEqual(
            config["abi_paths"]["0x" + "1" * 40],
            str(path),
        )

    def test_functions_separate_storage_getters(self):
        artifact = {
            "contractName": "Escrow",
            "abi": [
                {
                    "type": "function",
                    "name": "release",
                    "inputs": [],
                    "stateMutability": "nonpayable",
                },
                {
                    "type": "function",
                    "name": "balances",
                    "inputs": [{"type": "address"}],
                    "stateMutability": "view",
                },
                {
                    "type": "function",
                    "name": "escrow",
                    "inputs": [{"type": "uint256"}],
                    "stateMutability": "view",
                },
            ],
            "storageLayout": {
                "storage": [
                    {
                        "label": "balances",
                        "slot": "0",
                        "type": "t_mapping(t_address,t_uint256)",
                    },
                    {
                        "label": "escrow",
                        "slot": "1",
                        "type": "t_mapping(t_uint256,t_struct(Create))",
                    },
                ]
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "Escrow.json"
            path.write_text(json.dumps(artifact), encoding="utf-8")
            config = {
                "target": "0x" + "1" * 40,
                "target_contract": "Escrow",
                "abi_paths": {"0x" + "1" * 40: str(path)},
            }
            output = io.StringIO()
            with redirect_stdout(output):
                lk.run_functions(config)
        rendered = output.getvalue()
        self.assertIn("WRITE FUNCTIONS:", rendered)
        self.assertIn("STORAGE GETTERS:", rendered)
        self.assertNotIn(
            "balances(address)",
            rendered.split("WRITE FUNCTIONS:", 1)[1]
            .split("STORAGE GETTERS:", 1)[0],
        )

    def test_deps_default_project_shows_project_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "script").mkdir()
            (root / "src" / "Escrow.sol").write_text(
                "contract Escrow {}", encoding="utf-8"
            )
            (root / "script" / "Deploy.s.sol").write_text(
                'import "forge-std/Script.sol";\n'
                'import "../src/Escrow.sol";\n'
                'contract Deploy {}',
                encoding="utf-8",
            )
            old = os.getcwd()
            try:
                os.chdir(root)
                output = io.StringIO()
                with redirect_stdout(output):
                    lk.run_deps([])
            finally:
                os.chdir(old)
        self.assertIn(
            "script/Deploy.s.sol -> imports forge-std/Script.sol",
            output.getvalue(),
        )
        self.assertIn(
            "script/Deploy.s.sol -> imports ../src/Escrow.sol",
            output.getvalue(),
        )

    def test_help_long_alias(self):
        result = self.run_cli("--h")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Lowkey", result.stdout)
        self.assertIn("lk actor 0 Alice", result.stdout)

    def test_cli_failure_exit_codes(self):
        cases = [
            ("event", "Transfer(address,address,uint256)", "0xdeadbeef", "0x1"),
            ("target", "not-an-address"),
            ("receipt", "not-a-hash"),
            ("scan", "/path/does/not/exist"),
            ("definitely-not-a-command",),
            ("raw", "definitely-not-a-cast-command"),
            ("receipt", "0x" + "0" * 64),
            ("functions",),
            ("abi",),
            ("recon",),
            ("proxy",),
            ("snapshot",),
            ("gas",),
            ("namespace",),
            ("proof",),
            ("decode",),
            ("wizard",),
            ("test-gen",),
            ("matrix", "test", "missing-scenario"),
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

    def test_doctor_reports_missing_dependencies(self):
        with patch.object(lk.shutil, "which", return_value=None):
            self.assertEqual(lk.run_doctor(), 1)

    def test_solidity_identifier(self):
        self.assertEqual(
            lk.solidity_identifier("unauthorized release #1"),
            "unauthorized_release__1",
        )


    def test_humanize_value_is_explicit(self):
        raw = "1000000000000000000"
        self.assertEqual(lk.humanize_value(raw), raw)
        self.assertIn("1.0000 ETH", lk.humanize_value(raw, assume_wei=True))

    def test_abi_selector_uses_three_tuple(self):
        with patch.object(lk, "cast_output", return_value=(0, "0x12345678\n", "")):
            self.assertEqual(lk.abi_selector("foo(uint256)"), "0x12345678")

    def test_split_lab_options(self):
        values, actor, value, keep = lk.split_lab_options(
            ["release", "1", "0x" + "1" * 40, "--actor", "Alice", "--value", "1ether", "--keep"]
        )
        self.assertEqual(values, ["release", "1", "0x" + "1" * 40])
        self.assertEqual(actor, "Alice")
        self.assertEqual(value, "1ether")
        self.assertTrue(keep)

    def test_as_restores_previous_actor(self):
        config = {
            "actor": "Alice",
            "wallets": {"Alice": {"address": "0x" + "1" * 40}, "Bob": {"address": "0x" + "2" * 40}},
        }
        seen = {}

        def fake_dispatch(cmd, args, cfg, from_batch=False):
            seen["actor"] = cfg["actor"]
            return 0

        with patch.object(lk, "dispatch_command", side_effect=fake_dispatch):
            self.assertEqual(lk.run_as(config, ["Bob", "status"]), 0)
        self.assertEqual(seen["actor"], "Bob")
        self.assertEqual(config["actor"], "Alice")

    def test_probe_generates_actor_probe(self):
        config = {
            "target": "0x" + "3" * 40,
            "actor": "Alice",
            "wallets": {"Alice": {"address": "0x" + "1" * 40}},
        }
        captured = {}

        def fake_write(prefix, content):
            captured["prefix"] = prefix
            captured["content"] = content
            return "test/Lowkey_probe.t.sol"

        with patch.object(lk, "encode_target_call", return_value=("ping(uint256)", "abcdef")), \
             patch.object(lk, "write_generated_test", side_effect=fake_write), \
             patch.object(lk, "run_foundry", return_value=0):
            self.assertEqual(lk.run_probe(config, ["ping", "7", "--actor", "Alice"]), 0)
        self.assertIn("vm.startPrank", captured["content"])
        self.assertIn('hex"abcdef"', captured["content"])
        self.assertIn("ACTOR Alice", captured["content"])

    def test_state_diff_generates_recording(self):
        config = {
            "target": "0x" + "3" * 40,
            "actor": "Alice",
            "wallets": {"Alice": {"address": "0x" + "1" * 40}},
        }
        captured = {}

        def fake_write(prefix, content):
            captured["content"] = content
            return "test/Lowkey_state_diff.t.sol"

        with patch.object(lk, "encode_target_call", return_value=("ping()", "abcdef")), \
             patch.object(lk, "write_generated_test", side_effect=fake_write), \
             patch.object(lk, "run_foundry", return_value=0):
            self.assertEqual(lk.run_state_diff(config, ["ping"]), 0)
        self.assertIn("vm.startStateDiffRecording()", captured["content"])
        self.assertIn("vm.stopAndReturnStateDiff()", captured["content"])
        self.assertIn("Vm.StorageAccess", captured["content"])

    def test_selector_compare_uses_runtime_and_abi(self):
        target = "0x" + "1" * 40
        config = {
            "target": target,
            "abi_paths": {target: "/tmp/abi.json"},
            "target_contract": "Fixture",
        }
        abi = [{"type": "function", "name": "ping", "inputs": [{"type": "uint256"}]}]
        with patch.object(lk, "run_cast", return_value=lk.CommandResult("0x6000", 0)), \
             patch.object(lk, "load_abi", return_value=abi), \
             patch.object(
                 lk, "cast_output",
                 side_effect=[
                     (0, "0x12345678", ""),
                     (0, "0x12345678", ""),
                 ],
             ), \
             patch.object(lk, "abi_selector", return_value="0x12345678"):
            output = io.StringIO()
            with redirect_stdout(output):
                result = lk.run_selector_compare(config, [])
        self.assertEqual(result, 0)
        self.assertIn("RUNTIME-ONLY:", output.getvalue())
        self.assertIn("ABI-ONLY:", output.getvalue())




    def test_decode_calldata_auto_resolves_loaded_abi(self):
        config={"target":"0x"+"1"*40}
        abi=[{"type":"function","name":"ping","inputs":[{"type":"uint256"}]}]
        with patch.object(lk,"load_abi",return_value=abi), \
             patch.object(lk,"abi_selector",return_value="0x773acdef"), \
             patch.object(lk,"run_cast",return_value=lk.CommandResult("7",0)) as run:
            output=io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(lk.run_cast_deep(config,["decode-calldata","0x773acdef"+"0"*63+"7"]),0)
        self.assertEqual(
            run.call_args.args[0][:3],
            ["decode-calldata","ping(uint256)","0x773acdef"+"0"*63+"7"],
        )
        self.assertIn("Signature: ping(uint256)",output.getvalue())

    def test_cast_deep_commands(self):
        target="0x"+"1"*40
        config={"target":target,"abi_paths":{target:"/tmp/abi.json"}}
        calls=[]
        def fake_run(args,cfg,capture=False):
            calls.append(args)
            return 0
        with patch.object(lk,"run_cast",side_effect=fake_run), \
             patch.object(lk,"auto_abi_path",return_value="/tmp/abi.json"), \
             patch.object(lk,"resolve_function",return_value="ping(uint256)"):
            self.assertEqual(lk.run_cast_deep(config,["4byte","0x12345678"]),0)
            self.assertEqual(lk.run_cast_deep(config,["4byte-event","0x"+"a"*64]),0)
            self.assertEqual(lk.run_cast_deep(config,["4byte-calldata","0x12345678"]),0)
            self.assertEqual(lk.run_cast_deep(config,["access-list","ping","7"]),0)
            self.assertEqual(lk.run_cast_deep(config,["interface"]),0)
            self.assertEqual(lk.run_cast_deep(config,["constructor-args"]),0)
            self.assertEqual(lk.run_cast_deep(config,["creation-code"]),0)
            self.assertEqual(lk.run_cast_deep(config,["decode-calldata","0x12345678"]),0)
            self.assertEqual(lk.run_cast_deep(config,["abi-encode","uint256","7"]),0)
        self.assertTrue(any(x[0]=="interface" for x in calls))
        self.assertTrue(any(x[0]=="constructor-args" for x in calls))
        self.assertTrue(any(x[0]=="creation-code" for x in calls))
        self.assertTrue(any(x[0]=="access-list" for x in calls))

    def test_seams_command_surfaces_cross_signals(self):
        config={"target":"0x"+"1"*40}
        abi=[{
            "type":"function","name":"withdraw",
            "inputs":[{"name":"to","type":"address"}],
            "stateMutability":"payable"
        }]
        output=io.StringIO()
        with patch.object(lk,"load_abi",return_value=abi), redirect_stdout(output):
            self.assertEqual(lk.run_seams(config),0)
        rendered=output.getvalue()
        self.assertIn("state-write + address input",rendered)
        self.assertIn("state-write + asset/value flow",rendered)

    def test_matrix_test_executes_returned_generated_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            old=lk.WORKSPACE_DIR
            lk.WORKSPACE_DIR=tmp
            try:
                lk.run_matrix({},["init"])
                paths=lk.workspace_paths()
                lk.write_json_file(paths["matrix_actors"],{"Alice":{"address":"0x"+"1"*40}})
                lk.write_json_file(paths["matrix_scenarios"],[{
                    "name":"smoke","target":"0x"+"2"*40,
                    "function":"ping()","actor":"Alice","expected":"success"
                }])
                output=io.StringIO()
                with patch.object(lk,"run_foundry",return_value=0) as run, \
                     patch.object(lk,"write_generated_test",return_value=os.path.join(tmp,"Matrix_smoke.t.sol")):
                    with redirect_stdout(output):
                        self.assertEqual(lk.run_matrix(
                            {"target":"0x"+"2"*40,"abi_paths":{},"wallets":{}},
                            ["test","smoke"]
                        ),0)
                self.assertEqual(run.call_args.args[0][0],"test")
            finally:
                lk.WORKSPACE_DIR=old

    def test_txpool_uses_rpc_methods_not_cast_flag(self):
        config={"rpc":"http://127.0.0.1:8545"}
        with patch.object(lk,"rpc_json",side_effect=[
            {"pending":"0x1","queued":"0x2"},
            {"pending":{},"queued":{}},
        ]) as rpc_json:
            output=io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(lk.run_txpool(config, []),0)
                self.assertEqual(lk.run_txpool(config, ["content"]),0)
        self.assertEqual(rpc_json.call_args_list[0].args[:2], ("http://127.0.0.1:8545","txpool_status"))
        self.assertEqual(rpc_json.call_args_list[1].args[:2], ("http://127.0.0.1:8545","txpool_content"))

    def test_foundry_test_wrappers(self):
        with patch.object(lk, "run_foundry", return_value=0) as run:
            self.assertEqual(lk.run_fuzz(["--fuzz-runs", "10"]), 0)
            self.assertEqual(run.call_args.args[0][:1], ["test"])
            self.assertEqual(lk.run_invariant({}, ["--match-test", "invariant_x"]), 0)
        with patch.object(lk, "run_foundry", return_value=0) as run:
            self.assertEqual(lk.run_mutate(["--match-path", "test/X.t.sol"]), 0)
            self.assertEqual(run.call_args.args[0][:2], ["test", "--mutate"])
        with patch.object(lk, "run_foundry", return_value=0) as run:
            self.assertEqual(lk.run_symbolic(["emit"]), 0)
            self.assertEqual(run.call_args.args[0][:2], ["test", "--symbolic"])
            self.assertIn("--emit-regression", run.call_args.args[0])


    def test_cheatcode_reference_and_brutalize(self):
        output=io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(lk.run_cheatcodes(["store"]), 0)
        self.assertIn("vm.store", output.getvalue())
        with patch.object(lk, "run_foundry", return_value=0) as run:
            self.assertEqual(lk.run_brutalize(["--match-test", "testFoo"]), 0)
        self.assertEqual(run.call_args.args[0][:2], ["test", "--brutalize"])

    def test_probe_all_configured_actors(self):
        config={
            "target":"0x"+"3"*40,
            "actor":"Alice",
            "wallets":{
                "Alice":{"address":"0x"+"1"*40},
                "Bob":{"address":"0x"+"2"*40},
            },
        }
        captured={}
        def fake_write(prefix,content):
            captured["content"]=content
            return "test/Lowkey_probe.t.sol"
        with patch.object(lk, "encode_target_call", return_value=("ping()", "abcdef")), \
             patch.object(lk, "write_generated_test", side_effect=fake_write), \
             patch.object(lk, "run_foundry", return_value=0):
            self.assertEqual(lk.run_probe(config, ["ping"]), 0)
        self.assertIn("ACTOR Alice", captured["content"])
        self.assertIn("ACTOR Bob", captured["content"])


    def test_impersonated_actor_configuration(self):
        address="0x"+"1"*40
        config={"wallets":{},"actor":None,"rpc":"http://127.0.0.1:8545"}
        info={"url":"http://127.0.0.1:8545","client":"anvil/v1.8.3","accounts":[]}
        with patch.object(lk,"anvil_rpc_info",return_value=info), \
             patch.object(lk,"run_cast",return_value=lk.CommandResult("0x0",0)), \
             patch.object(lk,"save_config"):
            self.assertEqual(lk.run_impersonate(config,[address,"whale"]),0)
        self.assertEqual(config["actor"],"whale")
        self.assertEqual(config["wallets"]["whale"]["source"],"anvil-impersonated")

    def test_run_cast_uses_unlocked_for_impersonated_actor(self):
        target="0x"+"3"*40
        actor="0x"+"1"*40
        config={
            "target":target,
            "rpc":"http://127.0.0.1:8545",
            "actor":"whale",
            "wallets":{"whale":{"source":"anvil-impersonated","address":actor}},
        }
        with patch.object(lk,"cast_output",return_value=(0,"ok","")) as cast_output:
            self.assertEqual(lk.run_cast(["send","ping()"],config),0)
        sent_args=cast_output.call_args.args[0]
        self.assertIn("--unlocked",sent_args)
        self.assertIn(actor,sent_args)

    def test_proxy_aware_abi_discovery(self):
        target="0x"+"1"*40
        implementation="0x"+"2"*40
        artifact={
            "contractName":"Impl",
            "abi":[{"type":"function","name":"release","inputs":[],"stateMutability":"nonpayable"}],
            "deployedBytecode":{"object":"0x60016000"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/"Impl.json"
            path.write_text(json.dumps(artifact),encoding="utf-8")
            with patch.object(lk,"local_artifact_paths",return_value=[str(path)]), \
                 patch.object(lk,"effective_rpc",return_value="http://127.0.0.1:8545"), \
                 patch.object(lk,"discover_deployments",return_value=[]), \
                 patch.object(lk,"cast_output",side_effect=[
                     (0,implementation,""),
                     (0,"0x60016000",""),
                 ]):
                config={"target_contract":None,"abi_paths":{}}
                result=lk.auto_abi_path(target,config)
        self.assertEqual(result,str(path))
        self.assertEqual(config["target_contract"],"Impl")
        self.assertEqual(config["abi_paths"][target],str(path))

    def test_fork_status_without_fork_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            old=lk.FORK_FILE
            lk.FORK_FILE=os.path.join(tmp,"fork.json")
            try:
                output=io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(lk.run_fork(["status"]),0)
                self.assertIn("Fork: stopped",output.getvalue())
            finally:
                lk.FORK_FILE=old

    def test_symbolic_emit_alias(self):
        with patch.object(lk,"run_foundry",return_value=0) as run:
            self.assertEqual(lk.run_symbolic(["emit","--match-test","testFoo"]),0)
        self.assertIn("--emit-regression",run.call_args.args[0])

    def test_dispatch_exposes_lab_commands(self):
        config = {}
        calls = {}
        with patch.object(lk, "run_calldata", side_effect=lambda *_: calls.setdefault("calldata", 1)), \
             patch.object(lk, "run_probe", side_effect=lambda *_: calls.setdefault("probe", 1)), \
             patch.object(lk, "run_state_diff", side_effect=lambda *_: calls.setdefault("state-diff", 1)), \
             patch.object(lk, "run_fuzz", side_effect=lambda *_: calls.setdefault("fuzz", 1)), \
             patch.object(lk, "run_invariant", side_effect=lambda *_: calls.setdefault("invariant", 1)), \
             patch.object(lk, "run_mutate", side_effect=lambda *_: calls.setdefault("mutate", 1)), \
             patch.object(lk, "run_symbolic", side_effect=lambda *_: calls.setdefault("symbolic", 1)):
            lk.dispatch_command("calldata", ["0x12345678"], config)
            lk.dispatch_command("probe", ["ping"], config)
            lk.dispatch_command("state-diff", ["ping"], config)
            lk.dispatch_command("fuzz", [], config)
            lk.dispatch_command("invariant", [], config)
            lk.dispatch_command("mutate", [], config)
            lk.dispatch_command("symbolic", [], config)
        self.assertEqual(
            set(calls),
            {"calldata", "probe", "state-diff", "fuzz", "invariant", "mutate", "symbolic"},
        )

if __name__ == "__main__":
    unittest.main()
