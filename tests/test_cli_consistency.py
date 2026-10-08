import importlib.util
import io
import pathlib
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "lk.py"

spec = importlib.util.spec_from_file_location("lowkeycast_cli_consistency", MODULE)
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


class CliConsistencyTests(unittest.TestCase):
    def test_named_actor_resolves_for_address_argument(self):
        alice = "0x" + "1" * 40
        deployer = "0x" + "2" * 40
        config = {
            "actor": "Alice",
            "wallets": {
                "Alice": {
                    "source": "anvil-default",
                    "anvil_index": 1,
                    "address": alice,
                },
                "lab-deployer": {
                    "source": "anvil-default",
                    "anvil_index": 0,
                    "address": deployer,
                    "internal": True,
                },
            },
        }
        item = {"inputs": [{"name": "account", "type": "address"}]}
        self.assertEqual(lk.prepare_argument_values(config, item, ["Alice"]), [alice])
        self.assertEqual(lk.prepare_argument_values(config, item, ["Bob"]), ["Bob"])

    def test_project_target_name_resolves_for_address_argument(self):
        target = "0x" + "3" * 40
        config = {"actor": "Alice", "wallets": {"Alice": {"address": "0x" + "1" * 40}}, "targets": {"Fallback": target}}
        item = {"inputs": [{"name": "account", "type": "address"}]}
        with patch.object(lk, "actor_address", return_value=None), \
             patch.object(lk.audit_context, "foundry_project_root", return_value=pathlib.Path("/tmp/Fallback")):
            with patch.object(lk, "resolve_target_ref", return_value=target) as resolve_target:
                self.assertEqual(lk.prepare_argument_values(config, item, ["Fallback"]), [target])
                resolve_target.assert_called_once_with(config, "Fallback", pathlib.Path("/tmp/Fallback"))

    def test_actor_name_wins_over_target_name_for_address_argument(self):
        actor = "0x" + "1" * 40
        target = "0x" + "2" * 40
        config = {"actor": "Alice", "wallets": {"Alice": {"address": actor}}, "targets": {"Alice": target}}
        item = {"inputs": [{"name": "account", "type": "address"}]}
        with patch.object(lk, "actor_address", return_value=actor), \
             patch.object(lk, "resolve_target_ref", return_value=target) as resolve_target:
            self.assertEqual(lk.prepare_argument_values(config, item, ["Alice"]), [actor])
            resolve_target.assert_not_called()

    def test_storage_read_labels_actor_address(self):
        address = "0x" + "f" * 40
        config = {
            "target": "0x" + "3" * 40,
            "actor": "Alice",
            "wallets": {"Alice": {"address": address}},
        }
        types = {
            "t_address": {
                "label": "address",
                "numberOfBytes": 20,
            },
        }
        storage = [
            {
                "slot": "1",
                "offset": 0,
                "label": "owner",
                "type": "t_address",
            },
        ]
        with patch.object(lk, "storage_layout_details", return_value=(types, storage)):
            rendered = lk.format_storage_read(
                config,
                "1",
                "0x000000000000000000000000" + "f" * 40,
            )
        self.assertIn(f"Value: Alice ({address})", rendered)

    def test_address_labels_include_project_target_names(self):
        address = "0x" + "4" * 40
        config = {
            "target": address,
            "targets": {"Fallback": address},
        }
        with patch.object(lk, "target_aliases", return_value={"Fallback": address}):
            self.assertIn(
                f"Fallback ({address})",
                lk.apply_labels(address, config),
            )

    def test_storage_read_explains_slot_from_compiled_layout(self):
        raw = "0x000000000000000000000000" + "f39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        types = {
            "t_address": {
                "label": "address",
                "numberOfBytes": 20,
            },
        }
        storage = [
            {
                "slot": "1",
                "offset": 0,
                "label": "owner",
                "type": "t_address",
            },
        ]
        config = {"target": "0x" + "3" * 40}
        with patch.object(lk, "storage_layout_details", return_value=(types, storage)):
            rendered = lk.format_storage_read(config, "1", raw)

        self.assertIn("Slot:      1", rendered)
        self.assertIn("owner:", rendered)
        self.assertIn("Type:  address", rendered)
        self.assertIn(
            "Value: 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            rendered,
        )
        self.assertIn(f"Raw:       {raw}", rendered)

    def test_storage_command_uses_selected_target(self):
        target = "0x" + "3" * 40
        config = {
            "target": target,
            "rpc": "http://127.0.0.1:8545",
        }
        with patch.object(lk, "activate_project_target", return_value=target),              patch.object(lk, "storage_layout_details", return_value=({}, [])),              patch.object(lk, "cast_output", return_value=(0, "0x" + "4" * 64, "")) as cast_output:
            result = lk.dispatch_command("storage", ["1"], config)

        self.assertEqual(result, 0)
        cast_output.assert_called_once_with([
            "cast",
            "storage",
            target,
            "1",
            "--rpc-url",
            "http://127.0.0.1:8545",
        ])

    def test_slots_alias_uses_selected_target(self):
        target = "0x" + "3" * 40
        config = {
            "target": target,
            "rpc": "http://127.0.0.1:8545",
        }
        with patch.object(lk, "activate_project_target", return_value=target),              patch.object(lk, "storage_layout_details", return_value=({}, [])),              patch.object(lk, "cast_output", return_value=(0, "0x" + "4" * 64, "")) as cast_output:
            result = lk.dispatch_command("slots", ["1"], config)

        self.assertEqual(result, 0)
        cast_output.assert_called_once_with([
            "cast",
            "storage",
            target,
            "1",
            "--rpc-url",
            "http://127.0.0.1:8545",
        ])

    def test_named_target_can_be_used_as_explicit_read_target(self):
        target = "0x" + "3" * 40
        config = {
            "target": None,
            "targets": {"Fallback": target},
            "rpc_url": "http://127.0.0.1:8545",
        }
        abi_item = {"name": "getContribution", "type": "function", "inputs": [], "outputs": []}
        with patch.object(lk.audit_context, "foundry_project_root", return_value=pathlib.Path("/tmp/Fallback")), \
             patch.object(lk, "resolve_target_ref", return_value=target) as resolve_target, \
             patch.object(lk, "resolve_function", return_value="getContribution()"), \
             patch.object(lk, "load_abi", return_value=[abi_item]), \
             patch.object(lk, "cast_output", return_value=(0, "0x", "")) as cast_output:
            result = lk.run_cast(["call", "Fallback", "getContribution"], config, capture=True)

        self.assertEqual(result.code, 0)
        resolve_target.assert_called_once_with(config, "Fallback", root=pathlib.Path("/tmp/Fallback"))
        cast_output.assert_called_once_with([
            "cast",
            "call",
            target,
            "getContribution()",
            "--rpc-url",
            "http://127.0.0.1:8545",
        ])

    def test_internal_deployer_identity_is_available_with_active_actor(self):
        alice = "0x" + "1" * 40
        deployer = "0x" + "2" * 40
        config = {
            "actor": "Alice",
            "wallets": {
                "Alice": {"address": alice, "source": "anvil-default", "anvil_index": 1},
                "lab-deployer": {
                    "address": deployer,
                    "source": "anvil-default",
                    "anvil_index": 0,
                    "internal": True,
                },
            },
            "labels": {},
        }
        identities = lk._known_address_identities(config)
        self.assertEqual(identities[alice.lower()][0], "Alice")
        self.assertEqual(identities[deployer.lower()][0], "lab-deployer")

    def test_multi_actor_send_caps_at_ten_live_anvil_accounts(self):
        accounts = ["0x" + f"{index + 1:040x}" for index in range(12)]
        calls = []

        def fake_run_cast(args, config, capture=False):
            calls.append((list(args), config))
            return lk.CommandResult(
                "transactionHash 0x" + "1" * 64 + "\n"
                "blockNumber 8\n"
                "gasUsed 21000\n"
                "from " + config["wallets"][config["actor"]]["address"] + "\n"
                "to " + "0x" + "9" * 40 + "\n"
                "status 1",
                0,
            )

        with patch.object(lk, "anvil_rpc_info", return_value={"url": "http://127.0.0.1:8545", "accounts": accounts}), \
             patch.object(lk, "run_cast", side_effect=fake_run_cast), \
             patch.object(lk, "format_send_summary", return_value="TRANSACTION OK"):
            config = {
                "target": "0x" + "9" * 40,
                "wallets": {},
                "labels": {},
            }
            output = io.StringIO()
            with redirect_stdout(output):
                result = lk.run_multi_actor_send(
                    config,
                    ["contribute", "--value", "1"],
                )

        self.assertEqual(result, 0)
        self.assertEqual(len(calls), 10)
        self.assertEqual(
            [call_config["actor"] for _, call_config in calls],
            [f"anvil-{index}" for index in range(10)],
        )
        self.assertEqual(
            [call_config["wallets"][call_config["actor"]]["address"] for _, call_config in calls],
            accounts[:10],
        )
        self.assertTrue(all(call_config.get("_ephemeral") is True for _, call_config in calls))
        self.assertEqual(config["wallets"], {})
        rendered = output.getvalue()
        self.assertIn("Accounts detected: 12", rendered)
        self.assertIn("Accounts used:     10 (maximum 10)", rendered)
        self.assertIn("msg.sender changes per call", rendered)

    def test_multi_actor_send_rejects_repeat_flags(self):
        with patch.object(lk, "anvil_rpc_info", return_value={"url": "http://127.0.0.1:8545", "accounts": ["0x" + "1" * 40]}):
            result = lk.run_multi_actor_send(
                {"target": "0x" + "9" * 40},
                ["contribute", "--repeat", "2"],
            )
        self.assertEqual(result, 2)

    def test_send_eth_alias_normalizes_unitless_eth(self):
        self.assertEqual(
            lk.normalize_send_options(["contribute", "--eth", "0.001"]),
            ["contribute", "--value", "0.001 ether"],
        )

    def test_send_eth_alias_preserves_explicit_unit(self):
        self.assertEqual(
            lk.normalize_send_options(["contribute", "--eth", "100", "gwei"]),
            ["contribute", "--value", "100 gwei"],
        )

    def test_send_repeat_rejects_multi_call_without_changing_msg_sender(self):
        with self.assertRaisesRegex(ValueError, r"cannot repeat an exact call"):
            lk.normalize_send_options(["contribute", "--repeat", "2"])

    def test_send_repeat_error_is_not_double_prefixed(self):
        with patch.object(lk, "cast_output") as cast_output:
            result = lk.run_cast(
                ["send", "contribute", "--repeat", "5"],
                {"target": "0x" + "3" * 40},
                capture=True,
            )
        self.assertEqual(result.code, 2)
        self.assertTrue(str(result).startswith("Error: --repeat/--times cannot repeat"))
        self.assertNotIn("Error: Error:", str(result))
        cast_output.assert_not_called()

    def test_failed_evidence_command_does_not_refresh_poc(self):
        config = {"target": "0x" + "3" * 40}
        with patch.object(lk, "load_config", return_value=config), \
             patch.object(lk, "dispatch_command", return_value=2), \
             patch.object(lk, "runtime_sync_status", return_value={"status": "ok"}), \
             patch.object(lk.audit_context, "foundry_project_root", return_value=pathlib.Path("/tmp/Fallback")), \
             patch.object(lk, "_sync_audit_context"), \
             patch.object(lk, "refresh_generated_poc") as refresh_poc, \
             patch.object(lk, "_print_recommended_next_commands"), \
             patch.object(lk, "save_config"):
            with patch.object(lk.sys, "argv", ["lk", "send", "contribute", "--repeat", "5"]):
                with self.assertRaises(SystemExit) as exit_info:
                    lk.main()
        self.assertEqual(exit_info.exception.code, 2)
        refresh_poc.assert_not_called()

    def test_send_times_alias_matches_repeat(self):
        with self.assertRaisesRegex(ValueError, r"cannot repeat an exact call"):
            lk.normalize_send_options(["contribute", "--times", "2"])

    def test_send_help_documents_eth_and_repeat_boundary(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = lk.dispatch_command("send", ["--h"], {})
        self.assertEqual(code, 0)
        rendered = output.getvalue()
        self.assertIn("--eth <amount>", rendered)
        self.assertIn("--repeat <N>", rendered)
        self.assertIn("--actors", rendered)
        self.assertIn("msg.sender", rendered)


if __name__ == "__main__":
    unittest.main()
