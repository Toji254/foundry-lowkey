import importlib.util
import json
import os
import pathlib
from pathlib import Path
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

    def test_target_named_deployment_auto_selects_matching_broadcast(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            broadcast=root/"broadcast"
            out=root/"out"/"EthEscrow.s.sol"/"EscrowContract"
            broadcast.mkdir(parents=True)
            out.mkdir(parents=True)
            payload={
                "transactions":[
                    {
                        "transactionType":"CREATE",
                        "contractName":"Escrow",
                        "contractAddress":"0x"+"e"*40,
                        "hash":"0x"+"1"*64,
                    }
                ]
            }
            (broadcast/"EthEscrow.s.sol"/"31337").mkdir(parents=True)
            (broadcast/"EthEscrow.s.sol"/"31337"/"run-latest.json").write_text(json.dumps(payload),encoding="utf-8")
            artifact={"contractName":"Escrow","abi":[]}
            artifact_path=out/"Escrow.json"
            artifact_path.write_text(json.dumps(artifact),encoding="utf-8")
            old=os.getcwd()
            os.chdir(root)
            try:
                config={"target":None,"aliases":{},"targets":{},"abi_paths":{},"rpc":None}
                with patch.object(lk,"save_config"):
                    output=io.StringIO()
                    with redirect_stdout(output):
                        result=lk.run_auto_target(config,"escrow")
            finally:
                os.chdir(old)
        self.assertEqual(result,0)
        self.assertEqual(config["target"],"0x"+"e"*40)
        self.assertEqual(config["aliases"]["escrow"],"0x"+"e"*40)
        self.assertEqual(config["target_contract"],"Escrow")
        self.assertIn("Target selected: escrow ->",output.getvalue())

    def test_target_named_deployment_missing_is_error(self):
        with patch.object(
            lk,
            "discover_deployments",
            return_value=[{"contract":"Escrow","address":"0x"+"e"*40}],
        ):
            config={"aliases":{},"targets":{},"abi_paths":{}}
            with patch.object(lk,"save_config"):
                self.assertEqual(lk.run_auto_target(config,"Missing"),2)


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

    def test_mapping_human_view_decodes_struct_fields(self):
        target = "0x" + "1" * 40
        alice = "0x" + "2" * 40
        bob = "0x" + "3" * 40
        mapped_slot = "0x" + "ab" * 32
        types = {
            "t_mapping": {
                "encoding": "mapping",
                "key": "t_uint256",
                "value": "t_struct",
            },
            "t_uint256": {
                "label": "uint256",
                "encoding": "inplace",
                "numberOfBytes": "32",
            },
            "t_address": {
                "label": "address",
                "encoding": "inplace",
                "numberOfBytes": "20",
            },
            "t_struct": {
                "label": "struct Escrow.Create",
                "members": [
                    {"label": "creator", "slot": "0", "offset": 0, "type": "t_address"},
                    {"label": "recipient", "slot": "1", "offset": 0, "type": "t_address"},
                    {"label": "amount", "slot": "2", "offset": 0, "type": "t_uint256"},
                ],
            },
        }
        storage = [{"label": "escrow", "slot": "1", "type": "t_mapping"}]
        config = {
            "target": target,
            "wallets": {
                "Alice": {"address": alice},
                "Bob": {"address": bob},
            },
        }

        def word(address):
            return "0x" + "0" * 24 + address[2:]

        reads = [
            lk.CommandResult(word(alice), 0),
            lk.CommandResult(word(bob), 0),
            lk.CommandResult("0x" + format(10**18, "064x"), 0),
        ]
        output = io.StringIO()
        with patch.object(lk, "storage_layout_details", return_value=(types, storage)),              patch.object(lk, "run_cast", side_effect=reads):
            with redirect_stdout(output):
                result = lk.run_mapping_human_view(
                    config, "1", "uint256", "1", mapped_slot
                )

        self.assertTrue(result)
        rendered = output.getvalue()
        self.assertIn("Mapping:      escrow", rendered)
        self.assertIn("Key:          1", rendered)
        self.assertIn("creator", rendered)
        self.assertIn("Alice (0x" + "2" * 40 + ")", rendered)
        self.assertIn("Bob (0x" + "3" * 40 + ")", rendered)
        self.assertIn("1000000000000000000 wei [~1.0000 ETH]", rendered)
        self.assertIn("raw mapping slot", rendered)

    def test_local_cast_commands_do_not_receive_rpc_url(self):
        config = {"rpc": "http://127.0.0.1:8545"}
        expected_commands = [
            ["index", "uint256", "1", "1"],
            ["selectors", "0x6000"],
            ["constructor-args", "0x" + "1" * 40],
            ["creation-code", "0x" + "1" * 40],
        ]
        for args in expected_commands:
            with self.subTest(command=args[0]), patch.object(
                lk, "cast_output", return_value=(0, "0x" + "0" * 64, "")
            ) as cast_output:
                result = lk.run_cast(args, config, capture=True)
            self.assertEqual(result.code, 0)
            actual = cast_output.call_args.args[0]
            self.assertEqual(actual[:len(args)+1], ["cast", *args])
            self.assertNotIn("--rpc-url", actual)

    def test_mapping_rejects_failed_slot_calculation(self):
        target = "0x" + "1" * 40
        config = {"target": target}
        failure = lk.CommandResult(
            "error: unexpected argument '--rpc-url' found", 1
        )
        with patch.object(lk, "run_cast", return_value=failure) as run_cast:
            result = lk.run_mapping(config, "uint256", "1", "1")
        self.assertEqual(result, 2)
        run_cast.assert_called_once_with(
            ["index", "uint256", "1", "1"], config, capture=True
        )

    def test_mapping_reads_computed_slot_only_after_success(self):
        target = "0x" + "1" * 40
        config = {"target": target}
        slot = "0x" + "ab" * 32
        with patch.object(
            lk,
            "run_cast",
            side_effect=[lk.CommandResult(slot, 0), 0],
        ) as run_cast:
            result = lk.run_mapping(config, "uint256", "1", "1")
        self.assertEqual(result, 0)
        self.assertEqual(run_cast.call_args_list[0].args[0], ["index", "uint256", "1", "1"])
        self.assertEqual(run_cast.call_args_list[0].args[1]["target"], target)
        self.assertEqual(
            run_cast.call_args_list[1].args[0],
            ["st", slot],
        )

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

    def test_saved_relative_abi_path_resolves_from_outside_project(self):
        target = "0x" + "1" * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "project"
            outside = pathlib.Path(tmp) / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
            out = root / "out"
            out.mkdir()
            artifact_path = out / "Escrow.json"
            artifact_path.write_text(json.dumps({
                "contractName": "Escrow",
                "abi": [{"type": "function", "name": "release", "inputs": [], "stateMutability": "nonpayable"}],
            }), encoding="utf-8")
            config = {
                "target": target,
                "target_contract": "Escrow",
                "abi_paths": {target: "out/Escrow.json"},
                "project_roots": {target: str(root)},
            }
            old = os.getcwd()
            os.chdir(outside)
            try:
                resolved = lk.resolve_abi_path(config, target)
                self.assertEqual(resolved, str(artifact_path.resolve()))
                abi = lk.load_abi(target, config)
            finally:
                os.chdir(old)
        self.assertEqual(abi[0]["name"], "release")

    def test_relative_abi_path_migrates_to_remembered_project_root(self):
        target = "0x" + "2" * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
            out = root / "out"
            out.mkdir()
            artifact_path = out / "Escrow.json"
            artifact_path.write_text(json.dumps({
                "contractName": "Escrow",
                "abi": [],
            }), encoding="utf-8")
            config = {
                "target": target,
                "target_contract": "Escrow",
                "abi_paths": {target: "out/Escrow.json"},
                "project_roots": {},
            }
            old = os.getcwd()
            os.chdir(root)
            try:
                lk.load_abi(target, config)
            finally:
                os.chdir(old)
        self.assertEqual(config["project_roots"][target], str(root.resolve()))
        self.assertEqual(config["abi_paths"][target], str(artifact_path.resolve()))
        self.assertTrue(config.get("_config_dirty"))

    def test_auto_abi_path_uses_remembered_project_root(self):
        target = "0x" + "3" * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            outside = root / "outside"
            outside.mkdir(parents=True)
            (root / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
            out = root / "out"
            out.mkdir()
            artifact_path = out / "Escrow.json"
            artifact_path.write_text(json.dumps({
                "contractName": "Escrow",
                "abi": [],
            }), encoding="utf-8")
            config = {
                "target": target,
                "target_contract": "Escrow",
                "abi_paths": {},
                "project_roots": {target: str(root)},
            }
            old = os.getcwd()
            os.chdir(outside)
            try:
                with patch.object(lk, "effective_rpc", return_value=None):
                    path = lk.auto_abi_path(target, config)
            finally:
                os.chdir(old)
        self.assertEqual(path, str(artifact_path))
        
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

    def test_functions_fallback_to_forge_storage_layout(self):
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
                    "name": "escrow",
                    "inputs": [{"type": "uint256"}],
                    "stateMutability": "view",
                },
                {
                    "type": "function",
                    "name": "status",
                    "inputs": [],
                    "stateMutability": "view",
                },
            ],
        }
        forge_layout = {
            "storage": [
                {"label": "escrow", "slot": "1", "type": "t_mapping(t_uint256,t_struct(Create))"}
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "Escrow.json"
            path.write_text(json.dumps(artifact), encoding="utf-8")
            config = {
                "target": "0x" + "1" * 40,
                "target_contract": "Escrow",
                "abi_paths": {"0x" + "1" * 40: str(path)},
            }
            with patch.object(
                lk,
                "cast_output",
                return_value=(0, json.dumps(forge_layout), ""),
            ):
                output = io.StringIO()
                with redirect_stdout(output):
                    lk.run_functions(config)
        rendered = output.getvalue()
        self.assertIn("STORAGE GETTERS:", rendered)
        self.assertIn("escrow(uint256)  [public storage getter]", rendered)
        self.assertIn("READ FUNCTIONS:", rendered)
        self.assertIn("status()", rendered)
        self.assertNotIn(
            "escrow(uint256)",
            rendered.split("READ FUNCTIONS:", 1)[1]
            .split("STORAGE GETTERS:", 1)[0],
        )


    def test_functions_use_loaded_artifact_contract_name_for_storage_layout(self):
        artifact = {
            "contractName": "Escrow",
            "abi": [
                {
                    "type": "function",
                    "name": "escrow",
                    "inputs": [{"type": "uint256"}],
                    "stateMutability": "view",
                },
                {
                    "type": "function",
                    "name": "status",
                    "inputs": [],
                    "stateMutability": "view",
                },
            ],
        }
        forge_layout = {
            "storage": [
                {"label": "escrow", "slot": "1", "type": "t_mapping(t_uint256,t_struct(Create))"}
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "Escrow.json"
            path.write_text(json.dumps(artifact), encoding="utf-8")
            config = {
                "target": "0x" + "1" * 40,
                "target_contract": "StaleContractName",
                "abi_paths": {"0x" + "1" * 40: str(path)},
            }
            with patch.object(
                lk,
                "cast_output",
                return_value=(0, json.dumps(forge_layout), ""),
            ) as cast:
                output = io.StringIO()
                with redirect_stdout(output):
                    lk.run_functions(config)
        self.assertEqual(cast.call_args.args[0][:2], ["forge", "inspect"])
        self.assertEqual(cast.call_args.args[0][2], "Escrow")
        self.assertIn("STORAGE GETTERS:", output.getvalue())
        self.assertIn("escrow(uint256)  [public storage getter]", output.getvalue())

    def test_functions_fallback_to_source_public_storage_names(self):
        artifact = {
            "contractName": "Escrow",
            "abi": [
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
                {
                    "type": "function",
                    "name": "status",
                    "inputs": [],
                    "stateMutability": "view",
                },
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            src = root / "src"
            src.mkdir()
            (src / "EthEscrow.sol").write_text(
                """
                contract Escrow {
                    mapping(address => uint256) public balances;
                    mapping(uint256 => uint256) public escrow;
                    uint256 public status;
                }
                """,
                encoding="utf-8",
            )
            path = root / "Escrow.json"
            path.write_text(json.dumps(artifact), encoding="utf-8")
            config = {
                "target": "0x" + "1" * 40,
                "target_contract": "Escrow",
                "abi_paths": {"0x" + "1" * 40: str(path)},
            }
            old = os.getcwd()
            os.chdir(root)
            try:
                with patch.object(lk, "cast_output", return_value=(1, "", "")):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        lk.run_functions(config)
            finally:
                os.chdir(old)
        rendered = output.getvalue()
        self.assertIn("STORAGE GETTERS:", rendered)
        self.assertIn("balances(address)  [public storage getter]", rendered)
        self.assertIn("escrow(uint256)  [public storage getter]", rendered)
        self.assertIn("status()  [public storage getter]", rendered)



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
        self.assertIn("LOWKEY", result.stdout)
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

    def test_encode_target_call_rejects_placeholder(self):
        config={"target":"0x"+"1"*40}
        with patch.object(lk,"load_abi",return_value=[
            {"type":"function","name":"acceptescrow","inputs":[{"name":"accepted","type":"bool"}],"stateMutability":"nonpayable"}
        ]):
            with self.assertRaisesRegex(ValueError, "Replace '...'"):
                lk.encode_target_call(config,"acceptescrow",["..."])

    def test_encode_target_call_reports_argument_count(self):
        config={"target":"0x"+"1"*40}
        abi=[{
            "type":"function","name":"createescrow",
            "inputs":[{"name":"amount","type":"uint256"},{"name":"recipient","type":"address"}],
            "stateMutability":"payable"
        }]
        with patch.object(lk,"load_abi",return_value=abi):
            with self.assertRaisesRegex(ValueError, r"expects 2 argument\(s\), got 1"):
                lk.encode_target_call(config,"createescrow",["1 ether"])

    def test_split_lab_options_accepts_separated_eth_unit(self):
        values, actor, value, keep = lk.split_lab_options(
            ["release", "--actor", "Alice", "--value", "1", "ether"]
        )
        self.assertEqual(values, ["release"])
        self.assertEqual(actor, "Alice")
        self.assertEqual(value, "1 ether")
        self.assertFalse(keep)

    def test_encode_target_call_resolves_actor_name_for_address_argument(self):
        config = {
            "target": "0x" + "1" * 40,
            "wallets": {
                "Bob": {"address": "0x" + "2" * 40},
            },
        }
        abi = [{
            "type": "function",
            "name": "createescrow",
            "inputs": [
                {"name": "amount", "type": "uint256"},
                {"name": "recipient", "type": "address"},
            ],
            "stateMutability": "payable",
        }]
        with patch.object(lk, "load_abi", return_value=abi),              patch.object(lk, "cast_output", return_value=(0, "0xabcdef", "")) as cast:
            signature, encoded = lk.encode_target_call(
                config, "createescrow", ["1ether", "Bob"]
            )
        self.assertEqual(signature, "createescrow(uint256,address)")
        self.assertEqual(encoded, "abcdef")
        self.assertEqual(cast.call_args.args[0][-2:], ["1000000000000000000", "0x" + "2" * 40])

    def test_lab_flags_have_simple_aliases_and_auto_eth(self):
        values, actor, value, keep = lk.split_lab_options(
            ["createescrow", "1", "ether", "Bob", "--as", "Alice"]
        )
        self.assertEqual(values, ["createescrow", "1", "ether", "Bob"])
        self.assertEqual(actor, "Alice")
        self.assertEqual(value, "auto")
        self.assertFalse(keep)

        config={
            "target":"0x"+"1"*40,
            "wallets":{"Bob":{"address":"0x"+"2"*40}},
        }
        abi=[{
            "type":"function",
            "name":"createescrow",
            "inputs":[
                {"name":"amount","type":"uint256"},
                {"name":"recipient","type":"address"},
            ],
            "stateMutability":"payable",
        }]
        with patch.object(lk,"load_abi",return_value=abi):
            self.assertEqual(
                lk.resolve_lab_value(
                    config,
                    "createescrow(uint256,address)",
                    ["1","ether","Bob"],
                    "auto",
                ),
                "1 ether",
            )

    def test_run_cast_resolves_actor_name_for_address_argument(self):
        target="0x"+"1"*40
        config={
            "target":target,
            "wallets":{"Bob":{"address":"0x"+"2"*40}},
            "actor":"Alice",
        }
        abi=[{
            "type":"function",
            "name":"sendTo",
            "inputs":[{"name":"to","type":"address"}],
            "stateMutability":"nonpayable",
        }]
        with patch.object(lk,"load_abi",return_value=abi), \
             patch.object(lk,"cast_output",return_value=(0,"ok","")) as cast:
            self.assertEqual(lk.run_cast(["send","sendTo","Bob"],config),0)
        sent=cast.call_args.args[0]
        self.assertIn("sendTo(address)",sent)
        self.assertIn("0x"+"2"*40,sent)

    def test_encode_target_call_normalizes_ether_argument(self):
        config={
            "target":"0x"+"1"*40,
            "wallets":{"Bob":{"address":"0x"+"2"*40}},
        }
        abi=[{
            "type":"function",
            "name":"createescrow",
            "inputs":[
                {"name":"amount","type":"uint256"},
                {"name":"recipient","type":"address"},
            ],
            "stateMutability":"payable",
        }]
        with patch.object(lk,"load_abi",return_value=abi), \
             patch.object(lk,"cast_output",return_value=(0,"0xabcdef","")) as cast:
            lk.encode_target_call(config,"createescrow",["1ether","Bob"])
        sent=cast.call_args.args[0]
        self.assertIn("1000000000000000000",sent)
        self.assertIn("0x"+"2"*40,sent)


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

        def fake_write(prefix, content, announce=True):
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

        def fake_write(prefix, content, announce=True):
            captured["content"] = content
            return "test/Lowkey_state_diff.t.sol"

        with patch.object(lk, "encode_target_call", return_value=("ping()", "abcdef")), \
             patch.object(lk, "write_generated_test", side_effect=fake_write), \
             patch.object(lk, "run_foundry", return_value=lk.CommandResult("", 0)):
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
             patch.object(lk,"run_cast",return_value=0) as run:
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
        with patch.object(lk,"run_cast",side_effect=fake_run),              patch.object(lk,"auto_abi_path",return_value="/tmp/abi.json"),              patch.object(lk,"load_abi",return_value=[{"type":"function","name":"ping","inputs":[{"type":"uint256"}]}]),              patch.object(lk,"abi_selector",return_value="0x12345678"),              patch.object(lk,"resolve_function",return_value="ping(uint256)"):
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


    def test_storage_layout_inspection_uses_target_project_root(self):
        target = "0x" + "4" * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "project"
            outside = pathlib.Path(tmp) / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
            config = {
                "target": target,
                "target_contract": "Escrow",
                "abi_paths": {target: str(root / "out" / "Escrow.json")},
                "project_roots": {target: str(root)},
            }
            forge_layout = {
                "storage": [{"label": "escrow", "slot": "1", "type": "t_mapping"}],
                "types": {"t_mapping": {"encoding": "mapping", "key": "t_uint256", "value": "t_uint256"}},
            }
            old = os.getcwd()
            os.chdir(outside)
            try:
                with patch.object(
                    lk, "read_artifact", return_value={"contractName": "Escrow", "storageLayout": {}}
                ), patch.object(
                    lk.subprocess, "run",
                    return_value=subprocess.CompletedProcess(
                        ["forge"], 0, json.dumps(forge_layout), ""
                    ),
                ) as run:
                    types, storage = lk.storage_layout_details(config)
            finally:
                os.chdir(old)
        self.assertEqual(storage, forge_layout["storage"])
        self.assertEqual(types, forge_layout["types"])
        self.assertEqual(run.call_args.kwargs["cwd"], str(root))

    def test_fork_state_dump_and_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=os.path.join(tmp,"state.json")
            config={"rpc":"http://127.0.0.1:8545"}
            with patch.object(lk,"anvil_rpc_info",return_value={"url":config["rpc"]}), \
                 patch.object(lk,"rpc_json",side_effect=["0xabcdef",True]):
                self.assertEqual(lk.run_fork_state(config,["dump",path]),0)
                self.assertEqual(lk.run_fork_state(config,["load",path]),0)
            self.assertEqual(pathlib.Path(path).read_text(), "0xabcdef")

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

    def test_investigate_sets_shared_focus_and_suggests_tools(self):
        signal={
            "id":"SLITHER-ABC123",
            "tool":"slither",
            "title":"Low-level external call",
            "impact":"Informational",
            "confidence":"High",
            "file":"src/Vault.sol",
            "line":42,
            "function":"withdraw()",
            "description":"External call path",
            "meaning":"Review the external call boundary.",
            "why":"The callee controls execution.",
            "next":"Trace state changes.",
        }
        root=pathlib.Path.cwd()
        with patch.object(lk.audit_context,"set_focus",return_value=signal) as set_focus, \
             patch.object(lk.audit_context,"foundry_project_root",return_value=root):
            output=io.StringIO()
            with redirect_stdout(output):
                result=lk.run_investigate({},["SLITHER-ABC123"])
        self.assertEqual(result,0)
        set_focus.assert_called_once_with("SLITHER-ABC123",root)
        rendered=output.getvalue()
        self.assertIn("LOWKEY INVESTIGATION FOCUS",rendered)
        self.assertIn("lk changes withdraw()",rendered)


    def test_dispatch_uses_simple_audit_commands(self):
        with patch.object(lk, "run_audit", return_value=0) as audit,              patch.object(lk, "run_context", return_value=0) as context,              patch.object(lk, "run_signals", return_value=0) as findings,              patch.object(lk, "run_investigate", return_value=0) as focus:
            self.assertEqual(lk.dispatch_command("audit", [], {}), 0)
            self.assertEqual(lk.dispatch_command("findings", [], {}), 0)
            self.assertEqual(lk.dispatch_command("focus", ["SIG-1"], {}), 0)
            self.assertEqual(lk.dispatch_command("context", [], {}), 0)
        audit.assert_called_once()
        findings.assert_called_once()
        focus.assert_called_once()
        context.assert_called_once()


    def test_dispatch_exposes_shared_audit_commands(self):
        with patch.object(lk, "run_context", return_value=0) as context,              patch.object(lk, "run_signals", return_value=0) as signals:
            lk.dispatch_command("context", [], {})
            lk.dispatch_command("signals", [], {})
        context.assert_called_once()
        signals.assert_called_once()


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

    def test_parse_state_diff_output_extracts_changed_slots(self):
        output = """
[PASS] test_state_diff() (gas: 247291)
Logs:
  CALL createescrow(uint256,address)
  SUCCESS true
  ETH_SENT 1000000000000000000
  STORAGE_CHANGES 1
  SLOT
  0x""" + "1" * 64 + """
  FROM
  0x""" + "0" * 64 + """
  TO
  0x""" + "0" * 63 + "1" + """
"""
        parsed = lk.parse_state_diff_output(output)
        self.assertEqual(parsed["gas"], 247291)
        self.assertEqual(parsed["call"], "createescrow(uint256,address)")
        self.assertTrue(parsed["success"])
        self.assertEqual(parsed["eth_sent"], 10**18)
        self.assertEqual(len(parsed["slots"]), 1)
        self.assertEqual(parsed["slots"][0]["to"], "0x" + "0" * 63 + "1")

    def test_source_mapping_declarations_parses_public_struct_mapping(self):
        from tempfile import TemporaryDirectory

        source = """pragma solidity ^0.8.20;
contract Escrow {
    mapping(address => uint256 amount) public balances;
    mapping(uint256 value => Create Escrow) public escrow;

    enum status { waiting, funded, rejected, released }

    struct Create {
        address creator;
        address recipient;
        uint256 amount;
        status currentstatus;
    }
}
"""
        with TemporaryDirectory() as directory:
            path = Path(directory) / "Escrow.sol"
            path.write_text(source)
            declarations = lk.source_mapping_declarations(directory)

        self.assertEqual([item["label"] for item in declarations], ["balances", "escrow"])
        self.assertEqual(declarations[0]["key_type"], "address")
        self.assertEqual(declarations[0]["value_type"], "uint256")
        self.assertEqual(declarations[1]["key_type"], "uint256")
        self.assertEqual(declarations[1]["value_type"], "Create")
        self.assertEqual(
            [name for name, _ in declarations[1]["fields"]],
            ["creator", "recipient", "amount", "currentstatus"],
        )

    def test_storage_type_label_normalizes_internal_foundry_ids(self):
        types = {
            "t_address": {"label": "t_address"},
            "t_uint256": {"label": "t_uint256"},
        }
        self.assertEqual(lk.storage_type_label(types, "t_address"), "address")
        self.assertEqual(lk.storage_type_label(types, "t_uint256"), "uint256")

    def test_mapping_slot_match_decodes_struct_field_name(self):
        address = "0x" + "1" * 40
        changed_slot = "0x" + "2" * 64
        types = {
            "t_address": {"label": "address", "encoding": "inplace"},
            "t_uint256": {"label": "uint256", "encoding": "inplace"},
            "t_struct(Create)_storage": {
                "encoding": "inplace",
                "members": [
                    {"label": "creator", "slot": "0", "type": "t_address"},
                    {"label": "amount", "slot": "1", "type": "t_uint256"},
                ],
            },
            "t_mapping(uint256,t_struct(Create)_storage)": {
                "encoding": "mapping",
                "key": "t_uint256",
                "value": "t_struct(Create)_storage",
            },
        }
        storage = [{
            "label": "escrow",
            "slot": "1",
            "type": "t_mapping(uint256,t_struct(Create)_storage)",
        }]

        def fake_index(args, input_text=None):
            candidate = str(args[3])
            if candidate == "1":
                return 0, changed_slot, ""
            return 0, "0x" + "3" * 64, ""

        with patch.object(lk, "storage_layout_details", return_value=(types, storage)),              patch.object(lk, "configured_actor_addresses", return_value=[("Alice", address)]),              patch.object(lk, "cast_output", side_effect=fake_index):
            labels = lk.mapping_slot_matches(
                {"target": "0x" + "9" * 40, "wallets": {"Alice": {"address": address}}},
                "createescrow(uint256,address)",
                ["1 ether", "Bob"],
                address,
                [changed_slot],
            )

        self.assertEqual(
            labels[changed_slot.lower()],
            ("escrow[1].creator", "t_address"),
        )

    def test_dispatch_exposes_simple_audit_aliases(self):
        config={}
        calls={}
        with patch.object(lk,"run_probe",side_effect=lambda *_: calls.setdefault("try",1)), \
             patch.object(lk,"run_state_diff",side_effect=lambda *_: calls.setdefault("changes",1)), \
             patch.object(lk,"run_cast",side_effect=lambda *_: calls.setdefault("cast",1)):
            lk.dispatch_command("try",["release"],config)
            lk.dispatch_command("changes",["release"],config)
            lk.dispatch_command("read",["release"],config)
            lk.dispatch_command("send",["release"],config)
        self.assertEqual(set(calls),{"try","changes","cast"})


    def test_generated_test_path_is_stable_for_same_content(self):
        first = lk.generated_test_path("probe_release", "same-content")
        second = lk.generated_test_path("probe_release", "same-content")
        third = lk.generated_test_path("probe_release", "different-content")
        self.assertEqual(first, second)
        self.assertNotEqual(first, third)

    def test_state_diff_parser_accepts_fallback_write(self):
        output = """
[PASS] test_state_diff() (gas: 123)
Logs:
  CALL createescrow(uint256,address)
  SUCCESS true
  ETH_SENT 1000000000000000000
  FALLBACK_WRITES 1
  SLOT
  0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  FROM
  unknown
  TO
  0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  STORAGE_CHANGES 0
"""
        parsed = lk.parse_state_diff_output(output)
        self.assertEqual(parsed["fallback_writes"], 1)
        self.assertEqual(len(parsed["slots"]), 1)
        self.assertEqual(parsed["slots"][0]["from"], "unknown")

    def test_state_diff_parser_extracts_json_storage_write(self):
        slot = "0x" + "a" * 64
        previous = "0x" + "0" * 64
        new_value = "0x" + "0" * 63 + "7"
        output = (
            "[PASS] test_state_diff() (gas: 123)\\n"
            "Logs:\\n"
            "  CALL ping(uint256)\\n"
            "  SUCCESS true\\n"
            "  ETH_SENT 0\\n"
            "  STATE_DIFF_JSON_BEGIN\\n"
            '  {"storageAccesses":[{"slot":"' + slot + '","isWrite":true,"previousValue":"' + previous + '","newValue":"' + new_value + '","reverted":false}]}\\n'
            "  STATE_DIFF_JSON_END\\n"
            "  STORAGE_CHANGES 0\\n"
        )
        parsed = lk.parse_state_diff_output(output)
        self.assertTrue(parsed["state_diff_json"])
        self.assertEqual(len(parsed["slots"]), 1)
        self.assertEqual(parsed["slots"][0]["slot"], slot)


if __name__ == "__main__":
    unittest.main()

