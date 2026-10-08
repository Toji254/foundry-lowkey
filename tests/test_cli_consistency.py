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
        self.assertIn("msg.sender", rendered)


if __name__ == "__main__":
    unittest.main()
