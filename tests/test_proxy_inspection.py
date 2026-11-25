import contextlib
import io
import importlib.util
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
sys.path.insert(0, str(LOWKEY))
spec = importlib.util.spec_from_file_location("proxy_inspection_lk", LOWKEY / "lk.py")
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


TARGET = "0x" + "1" * 40
IMPLEMENTATION = "0x" + "2" * 40
BEACON = "0x" + "3" * 40
ADMIN = "0x" + "4" * 40
APP_GOV = "0x" + "5" * 40
ZERO_SLOT = "0x" + "0" * 64


def word(address):
    return "0x" + "0" * 24 + address[2:]


class ProxyInspectionTests(unittest.TestCase):
    def _run_cast(self, *, code="0x6000", implementation_slot=ZERO_SLOT,
                  beacon_slot=ZERO_SLOT, admin="Error: not a proxy",
                  beacon_implementation=None, app_governor=None):
        def fake(args, _config, capture=False):
            args = list(args)
            if args[0] == "code":
                return code
            if args[0] == "st":
                return (
                    implementation_slot
                    if args[1] == lk.EIP1967_IMPLEMENTATION_SLOT
                    else beacon_slot
                )
            if args[0] == "admin":
                return admin
            if args[0] == "call" and args[1] == BEACON:
                return beacon_implementation or "Error: beacon call failed"
            if args[0] == "call" and args[1] == TARGET:
                return app_governor or "Error: getter failed"
            return "Error: unsupported test call"
        return fake

    def test_uups_style_implementation_slot_is_proxy_without_admin(self):
        config = {"target": TARGET}
        with patch.object(
            lk, "run_cast",
            side_effect=self._run_cast(
                implementation_slot=word(IMPLEMENTATION),
                admin="Error: admin getter unavailable",
            ),
        ), patch.object(lk, "load_abi", return_value=[]):
            details = lk.inspect_proxy_details(config)
        self.assertTrue(details["is_proxy"])
        self.assertEqual(details["kind"], "ERC1967_IMPLEMENTATION_PROXY")
        self.assertEqual(details["implementation"].lower(), IMPLEMENTATION.lower())
        self.assertIsNone(details["admin"])

    def test_beacon_proxy_resolves_beacon_implementation_without_admin(self):
        config = {"target": TARGET}
        with patch.object(
            lk, "run_cast",
            side_effect=self._run_cast(
                beacon_slot=word(BEACON),
                beacon_implementation=word(IMPLEMENTATION),
            ),
        ), patch.object(lk, "load_abi", return_value=[]):
            details = lk.inspect_proxy_details(config)
        self.assertTrue(details["is_proxy"])
        self.assertEqual(details["kind"], "ERC1967_BEACON_PROXY")
        self.assertEqual(details["beacon"].lower(), BEACON.lower())
        self.assertEqual(
            details["beacon_implementation"].lower(), IMPLEMENTATION.lower()
        )
        self.assertIsNone(details["admin"])

    def test_eip1167_clone_is_not_misclassified_as_direct_contract(self):
        clone_code = (
            "0x363d3d373d3d3d363d73"
            + IMPLEMENTATION[2:]
            + "5af43d82803e903d91602b57fd5bf3"
        )
        config = {"target": TARGET}
        with patch.object(
            lk, "run_cast", side_effect=self._run_cast(code=clone_code)
        ), patch.object(lk, "load_abi", return_value=[]):
            details = lk.inspect_proxy_details(config)
        self.assertTrue(details["is_proxy"])
        self.assertEqual(details["kind"], "EIP1167_MINIMAL_CLONE")
        self.assertEqual(
            details["clone_implementation"].lower(), IMPLEMENTATION.lower()
        )

    def test_direct_contract_is_not_called_proxy_merely_because_admin_call_returns_address(self):
        config = {"target": TARGET}
        with patch.object(
            lk, "run_cast", side_effect=self._run_cast(admin=ADMIN)
        ), patch.object(lk, "load_abi", return_value=[]):
            details = lk.inspect_proxy_details(config)
        self.assertFalse(details["is_proxy"])
        self.assertEqual(details["kind"], "DIRECT_OR_UNKNOWN")

    def test_application_gov_getter_is_separate_from_proxy_admin(self):
        abi = [{
            "type": "function",
            "name": "gov",
            "inputs": [],
            "outputs": [{"type": "address", "name": ""}],
            "stateMutability": "view",
        }]
        config = {"target": TARGET}
        with patch.object(
            lk, "run_cast",
            side_effect=self._run_cast(
                implementation_slot=word(IMPLEMENTATION),
                admin=ADMIN,
                app_governor=APP_GOV,
            ),
        ), patch.object(lk, "load_abi", return_value=abi):
            details = lk.inspect_proxy_details(config)
        self.assertEqual(details["admin"].lower(), ADMIN.lower())
        self.assertEqual(
            details["application_governor"].lower(), APP_GOV.lower()
        )
        self.assertNotEqual(details["admin"].lower(), details["application_governor"].lower())

    def test_no_code_target_is_not_a_proxy(self):
        config = {"target": TARGET}
        with patch.object(
            lk, "run_cast", side_effect=self._run_cast(code="0x")
        ), patch.object(lk, "load_abi", return_value=[]):
            details = lk.inspect_proxy_details(config)
        self.assertFalse(details["has_code"])
        self.assertFalse(details["is_proxy"])
        self.assertEqual(details["kind"], "NO_CODE")

    def test_cast_address_decoder_handles_plain_and_abi_padded_addresses(self):
        self.assertEqual(lk._address_from_cast_result(IMPLEMENTATION), IMPLEMENTATION)
        self.assertEqual(lk._address_from_cast_result(word(IMPLEMENTATION)), IMPLEMENTATION)
        self.assertIsNone(lk._address_from_cast_result("Error: call reverted"))
        self.assertIsNone(lk._address_from_cast_result(word("0x" + "0" * 40)))

    def test_runtime_code_uses_rpc_scoped_cast_and_fails_closed(self):
        with patch.object(
            lk, "cast_output", return_value=(0, "0x6000", "")
        ) as cast:
            self.assertEqual(
                lk._runtime_code("http://127.0.0.1:8545", TARGET), "0x6000"
            )
        cast.assert_called_once_with([
            "cast", "code", TARGET, "--rpc-url", "http://127.0.0.1:8545"
        ])

        with patch.object(lk, "cast_output", return_value=(1, "", "rpc failed")):
            self.assertEqual(lk._runtime_code("http://127.0.0.1:8545", TARGET), "")

    def test_info_displays_beacon_implementation_from_shared_inspector(self):
        details = {
            "kind": "ERC1967_BEACON_PROXY",
            "implementation": None,
            "beacon": BEACON,
            "beacon_implementation": IMPLEMENTATION,
            "admin": None,
            "clone_implementation": None,
            "application_governor": APP_GOV,
            "evidence": ["non-zero ERC-1967 beacon slot"],
        }
        output = io.StringIO()
        with patch.object(lk, "run_chain"), \
             patch.object(lk, "run_cast", return_value="0x6000"), \
             patch.object(lk, "load_abi", return_value=[]), \
             patch.object(lk, "inspect_proxy_details", return_value=details):
            with contextlib.redirect_stdout(output):
                lk.run_info({"target": TARGET})

        self.assertIn(f"Beacon implementation: {IMPLEMENTATION}", output.getvalue())
        self.assertIn("Proxy evidence: non-zero ERC-1967 beacon slot", output.getvalue())

    def test_recon_distinguishes_minimal_clone_from_erc1967_proxy(self):
        details = {
            "kind": "EIP1167_MINIMAL_CLONE",
            "is_proxy": True,
            "implementation": IMPLEMENTATION,
            "beacon": None,
            "beacon_implementation": None,
            "admin": None,
            "application_governor": None,
            "evidence": ["minimal-proxy runtime bytecode embeds the implementation address"],
        }
        output = io.StringIO()
        with patch.object(lk, "run_cast", side_effect=[
            "1 ether", "0x6000", "0x" + "a" * 64, "1", "32"
        ]), \
             patch.object(lk, "inspect_proxy_details", return_value=details), \
             patch.object(lk, "inspect_clone") as legacy_clone:
            with contextlib.redirect_stdout(output):
                lk.run_recon({"target": TARGET})

        rendered = output.getvalue()
        self.assertIn("Proxy classification: EIP1167_MINIMAL_CLONE", rendered)
        self.assertIn("EIP-1967 proxy: NO", rendered)
        self.assertIn("EIP-1167 clone: YES", rendered)
        self.assertIn(f"Implementation: {IMPLEMENTATION}", rendered)
        legacy_clone.assert_not_called()


    def test_live_proxy_guard_accepts_beacon_and_clone_patterns(self):
        with patch.object(lk, "_runtime_code", return_value="0x6000"), \
             patch.object(
                 lk, "cast_output",
                 side_effect=[
                     (0, ZERO_SLOT, ""),
                     (0, word(BEACON), ""),
                 ],
             ):
            self.assertTrue(lk._live_target_is_proxy("http://127.0.0.1:8545", TARGET))

        clone_code = (
            "0x363d3d373d3d3d363d73"
            + IMPLEMENTATION[2:]
            + "5af43d82803e903d91602b57fd5bf3"
        )
        with patch.object(lk, "_runtime_code", return_value=clone_code), \
             patch.object(
                 lk, "cast_output",
                 side_effect=[
                     (0, ZERO_SLOT, ""),
                     (0, ZERO_SLOT, ""),
                 ],
             ):
            self.assertTrue(lk._live_target_is_proxy("http://127.0.0.1:8545", TARGET))


    def test_proxy_help_distinguishes_proxy_admin_from_application_governor(self):
        for command, expected in (
            ("proxy", ("EIP-1967", "EIP-1167", "gov()", "zero")),
            ("implementation", ("beacon", "minimal clone", "protocol readiness")),
            ("admin", ("EIP-1967", "gov()", "UUPS")),
        ):
            with self.subTest(command=command):
                output = []
                with patch.object(
                    lk, "print",
                    side_effect=lambda *args: output.append(" ".join(map(str, args))),
                    create=True,
                ):
                    code = lk._render_command_help([command])
                self.assertEqual(code, 0)
                rendered = "\\n".join(output).lower()
                for phrase in expected:
                    self.assertIn(phrase.lower(), rendered)



    def test_malformed_eip1967_slot_padding_is_not_treated_as_an_address(self):
        malformed = "0x" + "1" * 24 + IMPLEMENTATION[2:]
        self.assertIsNone(lk._address_from_slot(malformed))
        self.assertEqual(lk._address_from_slot(word(IMPLEMENTATION)), IMPLEMENTATION)


    def test_direct_contract_does_not_report_proxy_admin(self):
        with patch.object(
            lk, "run_cast", side_effect=self._run_cast(admin=ADMIN)
        ), patch.object(lk, "load_abi", return_value=[]):
            details = lk.inspect_proxy_details({"target": TARGET})
        self.assertFalse(details["is_proxy"])
        self.assertIsNone(details["admin"])


    def test_protocol_readiness_reports_zero_dependencies_and_initializer_separately(self):
        abi = [
            {"type": "function", "name": "router", "inputs": [], "outputs": [{"type": "address"}], "stateMutability": "view"},
            {"type": "function", "name": "vault", "inputs": [], "outputs": [{"type": "address"}], "stateMutability": "view"},
            {"type": "function", "name": "weth", "inputs": [], "outputs": [{"type": "address"}], "stateMutability": "view"},
            {"type": "function", "name": "usdg", "inputs": [], "outputs": [{"type": "address"}], "stateMutability": "view"},
            {"type": "function", "name": "paused", "inputs": [], "outputs": [{"type": "bool"}], "stateMutability": "view"},
            {"type": "function", "name": "totalSupply", "inputs": [], "outputs": [{"type": "uint256"}], "stateMutability": "view"},
            {"type": "function", "name": "initialize", "inputs": [{"type": "address"}], "outputs": [], "stateMutability": "nonpayable"},
        ]
        values = {
            "router()": "0x" + "0" * 64,
            "vault()": "0x" + "0" * 64,
            "weth()": word(APP_GOV),
            "usdg()": "Error: execution reverted",
            "paused()": "false",
        }
        def fake(args, _config, capture=False):
            if args[0] == "call":
                return values[args[2]]
            if args[0] == "code":
                return "0x6000"
            raise AssertionError("unexpected command " + str(args))
        with patch.object(lk, "run_cast", side_effect=fake):
            result = lk.inspect_protocol_readiness(
                {"target": TARGET}, abi, has_code=True
            )
        by_name = {item["name"]: item for item in result["getters"]}
        self.assertEqual(by_name["router"]["status"], "ZERO")
        self.assertEqual(by_name["vault"]["status"], "ZERO")
        self.assertEqual(by_name["weth"]["status"], "SET")
        self.assertEqual(by_name["weth"]["code_status"], "PRESENT")
        self.assertEqual(by_name["usdg"]["status"], "UNREADABLE")
        self.assertEqual(by_name["paused"]["status"], "FALSE")
        self.assertNotIn("totalSupply", by_name)
        self.assertEqual(result["initializer_entrypoints"], ["initialize(address)"])
        self.assertIn("do not establish protocol requirements", result["evidence_limit"])


    def test_initializer_presence_alone_does_not_trigger_configuration_calls_or_proxy_requirement(self):
        abi = [
            {"type": "function", "name": "initialize", "inputs": [], "outputs": [], "stateMutability": "nonpayable"},
        ]
        with patch.object(lk, "run_cast") as cast:
            result = lk.inspect_protocol_readiness(
                {"target": TARGET}, abi, has_code=True
            )
        cast.assert_not_called()
        self.assertEqual(result["initializer_entrypoints"], ["initialize()"])
        self.assertEqual(result["getters"], [])
        self.assertNotIn("requires_proxy", result)


    def test_non_view_dependency_named_function_is_never_called_for_readiness(self):
        abi = [
            {"type": "function", "name": "router", "inputs": [], "outputs": [{"type": "address"}], "stateMutability": "nonpayable"},
        ]
        with patch.object(lk, "run_cast") as cast:
            result = lk.inspect_protocol_readiness(
                {"target": TARGET}, abi, has_code=True
            )
        cast.assert_not_called()
        self.assertEqual(result["getters"], [])


    def test_proxy_slot_rpc_failures_are_unverified_not_a_direct_contract(self):
        def fake(args, _config, capture=False):
            if args[0] == "code":
                return "0x6000"
            if args[0] == "st":
                return lk.CommandResult("Error: RPC unavailable", 1)
            if args[0] == "admin":
                raise AssertionError("admin must not be queried without proxy evidence")
            raise AssertionError("unexpected command " + str(args))

        with patch.object(lk, "run_cast", side_effect=fake), \
             patch.object(lk, "load_abi", return_value=[]):
            details = lk.inspect_proxy_details({"target": TARGET})

        self.assertFalse(details["is_proxy"])
        self.assertEqual(details["kind"], "DIRECT_OR_UNKNOWN")
        self.assertEqual(details["implementation_slot_status"], "UNREADABLE")
        self.assertEqual(details["beacon_slot_status"], "UNREADABLE")
        self.assertEqual(details["proxy_detection_status"], "UNVERIFIED")
        self.assertTrue(any("proxy absence is not established" in item for item in details["evidence"]))


    def test_partial_eip1967_slot_read_is_not_reported_as_checked_direct(self):
        def fake(args, _config, capture=False):
            if args[0] == "code":
                return "0x6000"
            if args[0] == "st":
                if args[1] == lk.EIP1967_IMPLEMENTATION_SLOT:
                    return ZERO_SLOT
                return lk.CommandResult("Error: RPC unavailable", 1)
            return "Error: unsupported"

        with patch.object(lk, "run_cast", side_effect=fake), \
             patch.object(lk, "load_abi", return_value=[]):
            details = lk.inspect_proxy_details({"target": TARGET})

        self.assertEqual(details["implementation_slot_status"], "ZERO")
        self.assertEqual(details["beacon_slot_status"], "UNREADABLE")
        self.assertEqual(details["proxy_detection_status"], "PARTIALLY_CHECKED")


    def test_two_zero_proxy_slots_prove_only_no_supported_standard_pattern(self):
        with patch.object(lk, "run_cast", side_effect=self._run_cast()), \
             patch.object(lk, "load_abi", return_value=[]):
            details = lk.inspect_proxy_details({"target": TARGET})
        self.assertEqual(details["implementation_slot_status"], "ZERO")
        self.assertEqual(details["beacon_slot_status"], "ZERO")
        self.assertEqual(details["proxy_detection_status"], "CHECKED_NO_SUPPORTED_PATTERN")
        self.assertFalse(details["is_proxy"])


    def test_nonzero_candidate_dependency_is_checked_for_code_without_claiming_safety(self):
        abi = [
            {"type": "function", "name": "router", "inputs": [], "outputs": [{"type": "address"}], "stateMutability": "view"},
            {"type": "function", "name": "vault", "inputs": [], "outputs": [{"type": "address"}], "stateMutability": "view"},
            {"type": "function", "name": "weth", "inputs": [], "outputs": [{"type": "address"}], "stateMutability": "view"},
        ]
        calls = []
        values = {
            "router()": word(IMPLEMENTATION),
            "vault()": word(BEACON),
            "weth()": "0x" + "0" * 64,
        }

        def fake(args, _config, capture=False):
            calls.append(list(args))
            if args[0] == "call":
                return values[args[2]]
            if args[0] == "code" and args[1] == IMPLEMENTATION:
                return "0x6000"
            if args[0] == "code" and args[1] == BEACON:
                return "0x"
            raise AssertionError("unexpected command " + str(args))

        with patch.object(lk, "run_cast", side_effect=fake):
            result = lk.inspect_protocol_readiness({"target": TARGET}, abi, has_code=True)

        by_name = {item["name"]: item for item in result["getters"]}
        self.assertEqual(by_name["router"]["status"], "SET")
        self.assertEqual(by_name["router"]["code_status"], "PRESENT")
        self.assertEqual(by_name["vault"]["status"], "SET")
        self.assertEqual(by_name["vault"]["code_status"], "NO_CODE")
        self.assertEqual(by_name["weth"]["status"], "ZERO")
        self.assertEqual(by_name["weth"]["code_status"], "NOT_APPLICABLE_ZERO")
        self.assertFalse(any(call[0] == "code" and call[1] == "0x" + "0" * 40 for call in calls))
        self.assertIn("not proof that it is the intended", result["evidence_limit"])

if __name__ == "__main__":
    unittest.main()
