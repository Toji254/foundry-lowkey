import importlib.util
import io
import json
import pathlib
import sys
import unittest
from contextlib import redirect_stdout


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "break_engine.py"
PLAYBOOK = ROOT / "lowkey" / "break_playbook.py"

playbook_spec = importlib.util.spec_from_file_location("lowkey_break_playbook", PLAYBOOK)
playbook = importlib.util.module_from_spec(playbook_spec)
sys.modules[playbook_spec.name] = playbook
playbook_spec.loader.exec_module(playbook)

spec = importlib.util.spec_from_file_location("lowkey_break_engine", MODULE)
break_engine = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = break_engine
spec.loader.exec_module(break_engine)


class BreakEngineTests(unittest.TestCase):
    def test_parse_supports_evidence_explainer(self):
        opts = break_engine._parse_args(["--explain", "/tmp/example.json"])
        self.assertEqual(opts["explain"], "/tmp/example.json")

    def test_evidence_explainer_translates_replay_telemetry(self):
        import tempfile

        payload = {
            "family": "replay",
            "target": {
                "contract": "ConfidencePool",
                "address": "0x" + "1" * 40,
            },
            "function": "withdraw()",
            "forge_returncode": 0,
            "harness": "/tmp/Lowkey_Break_ConfidencePool.t.sol",
            "research_basis": {
                "title": "Replay / repeat-claim abuse",
                "basis": "claim, withdraw, redeem, release, payout and state-transition paths",
            },
            "output_tail": "\n".join([
                "LOWKEY_BREAK_FAMILY replay",
                "FIRST_SUCCESS false",
                "SECOND_SUCCESS false",
                "TOTAL_ATTACKER_GAIN 0",
                "TOTAL_TARGET_OUTFLOW 0",
                "ENTITLEMENT_READ_OK true",
                "ENTITLEMENT_BEFORE 0",
                "ENTITLEMENT_AFTER_FIRST 0",
                "ENTITLEMENT_AFTER_SECOND 0",
                "LOWKEY_BREAK false",
            ]),
        }

        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "evidence.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                result = break_engine._explain_evidence(str(path))

        rendered = output.getvalue()
        self.assertEqual(result, 0)
        self.assertIn("ATTACK EXECUTED — NO BREAK", rendered)
        self.assertIn("Target rejected the attempted call(s), so replay was not demonstrated.", rendered)
        self.assertIn("Attacker gain", rendered)
        self.assertIn("The target rejected the attempted call(s), so replay was not demonstrated.", rendered)
        self.assertIn("This does NOT prove withdraw/redeem is secure", rendered)

    def test_parse_explain_without_path_uses_latest(self):
        opts = break_engine._parse_args(["--explain"])
        self.assertEqual(opts["explain"], "latest")

    def test_parse_supports_function_system_and_until_found(self):
        opts = break_engine._parse_args([
            "--function", "withdraw(address,uint256)",
            "--system",
            "--until-found",
            "--rounds", "7",
            "--depth", "8",
            "--seed", "42",
        ])
        self.assertEqual(opts["function"], "withdraw(address,uint256)")
        self.assertTrue(opts["system"])
        self.assertTrue(opts["until_found"])
        self.assertEqual(opts["max_rounds"], 7)
        self.assertEqual(opts["depth"], 8)
        self.assertEqual(opts["seed"], 42)

    def test_generic_array_expression_is_supported_for_dynamic_arrays(self):
        self.assertEqual(
            break_engine._basic_solidity_expr("address[]", "[]"),
            "new address[](0)",
        )
    def test_generic_array_expression_is_supported_for_dynamic_arrays(self):
        self.assertEqual(
            break_engine._basic_solidity_expr("address[]", "[]"),
            "new address[](0)",
        )
        self.assertEqual(
            break_engine._basic_solidity_expr("uint256[]", "[]"),
            "new uint256[](0)",
        )
        self.assertEqual(
            break_engine._basic_solidity_expr("bytes[]", "[]"),
            "new bytes[](0)",
        )

    def test_lifecycle_functions_do_not_get_irrelevant_generic_families(self):
        initialize = {
            "name": "initialize",
            "inputs": [{"name": "accounts", "type": "address[]"}],
            "stateMutability": "nonpayable",
        }
        families = break_engine._families_for_function(initialize, None)
        self.assertIn("boundary", families)
        self.assertIn("access", families)
        self.assertIn("upgrade", families)
        self.assertIn("proxy", families)
        self.assertNotIn("reentrancy", families)
        self.assertNotIn("replay", families)
        self.assertNotIn("accounting", families)

    def test_function_scoped_shortcut(self):
        opts = break_engine._parse_args(["withdraw", "replay"])
        self.assertEqual(opts["function"], "withdraw")
        self.assertEqual(opts["family"], "replay")

    def test_attack_library_contains_core_public_audit_classes(self):
        required = {
            "reentrancy", "replay", "access", "accounting", "boundary",
            "time", "upgrade", "signature", "oracle", "economic",
            "erc20", "proxy", "storage", "dos",
        }
        self.assertTrue(required.issubset(set(break_engine.ATTACK_FAMILIES)))

    def test_access_probe_treats_asset_claim_paths_as_privileged_candidates(self):
        self.assertRegex("withdraw", break_engine.PRIVILEGED_RE)
        self.assertRegex("claim", break_engine.PRIVILEGED_RE)
        self.assertRegex("redeem", break_engine.PRIVILEGED_RE)
        self.assertRegex("release", break_engine.PRIVILEGED_RE)

    def test_sensitive_function_scoring_prioritizes_claim_paths(self):
        claim = {"name": "withdraw", "inputs": [], "stateMutability": "nonpayable"}
        ordinary = {"name": "setMetadata", "inputs": [], "stateMutability": "nonpayable"}
        self.assertLess(
            break_engine._score_function(claim)[0],
            break_engine._score_function(ordinary)[0],
        )

    def test_parse_supports_short_pattern_selector(self):
        opts = break_engine._parse_args(["--pattern", "REENT-001"])
        self.assertEqual(opts["pattern"], "REENT-001")

    def test_public_finding_playbook_is_cross_language(self):
        self.assertGreaterEqual(len(playbook.FINDING_PATTERNS), 30)
        ids = {item.id for item in playbook.FINDING_PATTERNS}
        self.assertIn("ORACLE-001", ids)
        self.assertIn("VAULT-001", ids)
        self.assertIn("BRIDGE-001", ids)
        vyper = {"languages": {"vyper": 4}, "stacks": ["vyper"]}
        self.assertEqual(playbook.backend_for_project(vyper), "evm")
        patterns = playbook.patterns_for(project=vyper, function_name="deposit", source_text="raw_call")
        self.assertTrue(any(item.id == "REENT-001" for item in patterns))

    def test_native_backend_selection_does_not_assume_anvil(self):
        self.assertEqual(playbook.backend_for_project({"languages": {"cairo": 4}, "stacks": ["cairo-starknet"]}), "cairo-starknet")
        self.assertEqual(playbook.backend_for_project({"languages": {"move": 2}, "stacks": ["move"]}), "move")
        self.assertEqual(playbook.backend_for_project({"languages": {"rust": 8}, "stacks": ["solana-anchor"]}), "solana-anchor")

    def test_forge_match_path_is_project_relative(self):
        from tempfile import TemporaryDirectory
        from unittest.mock import patch

        with TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp).resolve()
            harness = root / "test" / "Lowkey_Break_withdraw_replay.t.sol"
            harness.parent.mkdir(parents=True, exist_ok=True)
            harness.write_text("contract Test {}\n", encoding="utf-8")

            class AuditContext:
                def foundry_project_root(self):
                    return root

            class Host:
                audit_context = AuditContext()

                def tool_path(self, name):
                    return name

            fake = type("Completed", (), {
                "returncode": 0,
                "stdout": "LOWKEY_BREAK false",
                "stderr": "",
            })()

            with patch.object(break_engine.subprocess, "run", return_value=fake) as run:
                break_engine._forge_run(
                    Host(),
                    {},
                    str(harness),
                    "http://127.0.0.1:8545",
                    {"stacks": ["foundry"], "native": {"forge": True}},
                )

            command = run.call_args.args[0]
            match_index = command.index("--match-path")
            self.assertEqual(command[match_index + 1], "test/Lowkey_Break_withdraw_replay.t.sol")
            self.assertNotIn(str(root), command[match_index + 1])

    def test_generated_break_harness_avoids_checksum_sensitive_address_literals(self):
        target = break_engine.Target("Tipjar", "0x5fbdb2315678afecb367f032d93f642f64180aa3")
        fn = {"name": "withdraw", "inputs": [], "stateMutability": "nonpayable"}
        body = break_engine._render_reentrancy_test(
            target, fn, "withdraw()", [], 3
        )
        self.assertIn("address(uint160(0x005fbdb2315678afecb367f032d93f642f64180aa3))", body)
        self.assertNotIn("address(0x5fbdb2315678afecb367f032d93f642f64180aa3)", body)
        # Reentrancy uses the generated hostile wrapper as the caller; it does
        # not need the repeat/accounting harness's ATTACKER constant.
        self.assertIn("LowkeyBreakReentrant hostile = new LowkeyBreakReentrant(TARGET);", body)
        funded = break_engine._render_reentrancy_test(
            target, fn, "withdraw()", [], 3, seed_fund="10 ether"
        )
        self.assertIn("vm.deal(TARGET, 10 ether);", funded)
        # Funding-only reentrancy probes use the hostile wrapper's outer attack
        # call; there is no setup call unless a setup signature is supplied.
        self.assertIn('address(hostile).call{value: 1 wei}', funded)


    def test_fund_target_compact_amount_is_normalized_for_solidity(self):
        self.assertEqual(break_engine._solidity_amount_literal("10ether"), "10 ether")
        self.assertEqual(break_engine._solidity_amount_literal("500gwei"), "500 gwei")
        with self.assertRaises(ValueError):
            break_engine._solidity_amount_literal("10 apples")

    def test_reentrancy_harness_does_not_mask_target_reverts(self):
        target = break_engine.Target("Tipjar", "0x5fbdb2315678afecb367f032d93f642f64180aa3")
        fn = {
            "name": "withdraw",
            "inputs": [
                {"name": "recipient", "type": "address"},
                {"name": "amount", "type": "uint256"},
            ],
            "stateMutability": "nonpayable",
        }
        body = break_engine._render_reentrancy_test(
            target,
            fn,
            "withdraw(address,uint256)",
            ["0x1111111111111111111111111111111111111111", "1"],
            3,
            setup_signature="deposit()",
            seed_fund="10ether",
        )
        self.assertIn("emit TargetCall", body)
        self.assertNotIn('require(ok, "seed call reverted")', body)
        self.assertNotIn('require(ok, "outer attack reverted")', body)
        self.assertIn("SETUP_VALUE_WEI", body)

        self.assertIn("console2.log(\"SETUP_VALUE_WEI\", uint256(10 ether));", body)

        self.assertIn("lastSeedSuccess = ok;", body)
        self.assertIn("lastAttackSuccess = ok;", body)
        self.assertIn('console2.log("TARGET_OUTER_SUCCESS", hostile.lastAttackSuccess());', body)
        self.assertIn('console2.log("ATTACKER_WITHDRAW_RECEIVED", received);', body)
    def test_family_generator_exception_becomes_blocked(self):
        target = break_engine.Target("ConfidencePool", "0x" + "1" * 40)
        fn = {
            "name": "initialize",
            "inputs": [{"name": "accounts", "type": "address[]"}],
            "stateMutability": "nonpayable",
        }

        def exploding(*args, **kwargs):
            raise ValueError("complex ABI type 'address[]' needs a specialized attack generator")

        original = break_engine._run_family
        break_engine._run_family = exploding
        try:
            result = break_engine._safe_run_family(
                type("Host", (), {"format_signature": lambda self, item: "initialize(address[])"})(),
                {},
                "http://127.0.0.1:8545",
                target,
                fn,
                "reentrancy",
                {},
                None,
                {},
            )
        finally:
            break_engine._run_family = original

        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.family, "reentrancy")
        self.assertIn("Attack generator failed safely", result.summary)
        self.assertEqual(result.detail["error_type"], "ValueError")

    def test_result_parser_surfaces_missing_telemetry(self):
        target = break_engine.Target("Tipjar", "0x" + "1" * 40)
        observed = break_engine._result_from_output(
            type("Host", (), {})(),
            family="reentrancy",
            target=target,
            function="withdraw(address,uint256)",
            output="Error: Compiler run failed:\nError (1234): bad harness",
            evidence_path="/tmp/evidence.json",
        )
        self.assertEqual(observed.status, "BLOCKED")
        self.assertIn("Compiler run failed", observed.summary)

    def test_reentrancy_harness_exposes_seed_revert_telemetry(self):
        target = break_engine.Target("Tipjar", "0x" + "1" * 40)
        fn = {
            "name": "withdraw",
            "inputs": [
                {"name": "recipient", "type": "address"},
                {"name": "amount", "type": "uint256"},
            ],
            "stateMutability": "nonpayable",
        }
        body = break_engine._render_reentrancy_test(
            target,
            fn,
            "withdraw(address,uint256)",
            ["0x1111111111111111111111111111111111111111", "1"],
            3,
            setup_signature="deposit()",
            seed_fund="10ether",
        )
        self.assertIn("lastSeedReturndata", body)
        self.assertIn("lastAttackReturndata", body)
        self.assertIn("TARGET_SETUP_RETURNDATA_LENGTH", body)
        self.assertIn("TARGET_CODE_LENGTH", body)
        self.assertIn("TARGET_BALANCE_AFTER_SETUP", body)

    def test_entitlement_getter_discovery_prefers_balances(self):
        functions = [
            {
                "name": "foo",
                "inputs": [{"name": "who", "type": "address"}],
                "outputs": [{"name": "", "type": "uint256"}],
                "stateMutability": "view",
            },
            {
                "name": "balances",
                "inputs": [{"name": "who", "type": "address"}],
                "outputs": [{"name": "", "type": "uint256"}],
                "stateMutability": "view",
            },
        ]
        self.assertEqual(
            break_engine._find_entitlement_getter_signature(functions),
            "balances(address)",
        )

    def test_reentrancy_renderer_tracks_actual_setup_result_and_entitlement(self):
        target = break_engine.Target("Tipjar", "0x" + "1" * 40)
        fn = {
            "name": "withdraw",
            "inputs": [
                {"name": "recipient", "type": "address"},
                {"name": "amount", "type": "uint256"},
            ],
            "stateMutability": "nonpayable",
        }
        body = break_engine._render_reentrancy_test(
            target,
            fn,
            "withdraw(address,uint256)",
            ["0x1111111111111111111111111111111111111111", "1"],
            3,
            setup_signature="deposit()",
            seed_fund="10ether",
            entitlement_signature="balances(address)",
        )
        self.assertIn("lastSeedSuccess = ok;", body)
        self.assertIn("targetBalanceBeforeSetup", body)
        self.assertIn("targetBalanceAfterSetup", body)
        self.assertIn("ENTITLEMENT_AFTER_SETUP", body)
        self.assertIn("ENTITLEMENT_BEFORE_ATTACK", body)
        self.assertIn("ENTITLEMENT_AFTER_ATTACK", body)
        self.assertIn("exceededEntitlement", body)

    def test_forge_run_retries_stack_too_deep_with_ir(self):
        from tempfile import TemporaryDirectory
        from unittest.mock import patch

        with TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp).resolve()
            harness = root / "test" / "Lowkey_Break.t.sol"
            harness.parent.mkdir(parents=True, exist_ok=True)
            harness.write_text("contract Test {}\n", encoding="utf-8")

            class AuditContext:
                def foundry_project_root(self):
                    return root

            class Host:
                audit_context = AuditContext()
                def tool_path(self, name):
                    return name

            first = type("Completed", (), {
                "returncode": 1,
                "stdout": "",
                "stderr": "Error: Stack too deep. Try compiling with --via-ir",
            })()
            second = type("Completed", (), {
                "returncode": 0,
                "stdout": "LOWKEY_BREAK false",
                "stderr": "",
            })()

            with patch.object(break_engine.subprocess, "run", side_effect=[first, second]) as run:
                result = break_engine._forge_run(
                    Host(),
                    {},
                    str(harness),
                    "http://127.0.0.1:8545",
                    {"stacks": ["foundry"], "native": {"forge": True}},
                )

            self.assertEqual(result.returncode, 0)
            self.assertEqual(run.call_count, 2)
            retry = run.call_args_list[1].args[0]
            self.assertIn("--via-ir", retry)
            self.assertIn("--optimize", retry)

    def test_result_parser_distinguishes_target_rejection_before_callback(self):
        target = break_engine.Target("Tipjar", "0x" + "1" * 40)
        observed = break_engine._result_from_output(
            type("Host", (), {})(),
            family="reentrancy",
            target=target,
            function="withdraw(address,uint256)",
            output=(
                "LOWKEY_BREAK_FAMILY reentrancy\n"
                "TARGET_REJECTED_ATTACK true\n"
                "TARGET_REVERT_DATA_PRESENT false\n"
                "REENTRY_REACHED false\n"
                "LOWKEY_BREAK false"
            ),
            evidence_path="/tmp/evidence.json",
        )
        self.assertEqual(observed.status, "OBSERVED")
        self.assertIn("rejected the attack before the callback boundary", observed.summary)
        self.assertIn("No revert data was returned", observed.summary)

    def test_repeat_renderer_targets_attacker_and_seeds_entitlement(self):
        target = break_engine.Target("Tipjar", "0x" + "1" * 40)
        fn = {
            "name": "withdraw",
            "inputs": [
                {"name": "recipient", "type": "address"},
                {"name": "amount", "type": "uint256"},
            ],
            "stateMutability": "nonpayable",
        }
        body = break_engine._render_repeat_test(
            target,
            fn,
            "withdraw(address,uint256)",
            ["0x2222222222222222222222222222222222222222", "1"],
            "0",
            "accounting",
            "10ether",
            setup_signature="deposit()",
            entitlement_signature="balances(address)",
        )
        self.assertIn("address(ATTACKER)", body)
        self.assertIn("abi.encodeWithSignature(\"deposit()\")", body)
        self.assertIn('TARGET.call{value: 10 ether}(setupData)', body)
        self.assertIn('abi.encodeWithSignature("balances(address)", address(ATTACKER))', body)
        self.assertIn("totalGain > entitlementBefore", body)
        self.assertNotIn("if (second && secondGain > 0 && secondOutflow > 0)", body)

    def test_repeat_renderer_funds_attacker_before_payable_setup(self):
        target = break_engine.Target("Tipjar", "0x" + "1" * 40)
        fn = {
            "name": "withdraw",
            "inputs": [{"name": "recipient", "type": "address"}, {"name": "amount", "type": "uint256"}],
            "stateMutability": "nonpayable",
        }
        body = break_engine._render_repeat_test(
            target,
            fn,
            "withdraw(address,uint256)",
            ["0x2222222222222222222222222222222222222222", "1"],
            "0",
            "accounting",
            "10ether",
            setup_signature="deposit()",
            entitlement_signature="balances(address)",
        )
        deal_pos = body.index("vm.deal(ATTACKER, 100 ether);")
        setup_pos = body.index("abi.encodeWithSignature(\"deposit()\")")
        self.assertLess(deal_pos, setup_pos)

    def test_repeat_renderer_logs_raw_revert_data_for_generic_diagnostics(self):
        target = break_engine.Target("Vault", "0x" + "1" * 40)
        fn = {
            "name": "claim",
            "inputs": [{"name": "amount", "type": "uint256"}],
            "stateMutability": "nonpayable",
        }
        body = break_engine._render_repeat_test(
            target,
            fn,
            "claim(uint256)",
            ["1"],
            "0",
            "replay",
            "10ether",
            setup_signature="deposit()",
            entitlement_signature="credit(address)",
        )
        self.assertIn("console2.logBytes(setupReturndata);", body)
        self.assertIn("console2.logBytes(firstReturndata);", body)
        self.assertIn("console2.logBytes(secondReturndata);", body)

    def test_repeat_renderer_declares_entitlement_telemetry_without_getter(self):
        target = break_engine.Target("Vault", "0x" + "1" * 40)
        fn = {
            "name": "claim",
            "inputs": [{"name": "amount", "type": "uint256"}],
            "stateMutability": "nonpayable",
        }
        body = break_engine._render_repeat_test(
            target,
            fn,
            "claim(uint256)",
            ["1"],
            "0",
            "accounting",
            None,
            setup_signature=None,
            entitlement_signature=None,
        )
        self.assertIn("uint256 entitlementBefore = 0;", body)
        self.assertIn("bool entitlementReadOk = false;", body)
        self.assertIn("uint256 entitlementAfterFirst = 0;", body)
        self.assertIn("uint256 entitlementAfterSecond = 0;", body)

    def test_result_parser_decodes_custom_error_from_target_abi(self):
        target = break_engine.Target("Vault", "0x" + "1" * 40)
        error_abi = {
            "type": "error",
            "name": "Unauthorized",
            "inputs": [{"name": "caller", "type": "address"}],
            "selector": "0x12345678",
        }
        selector = "12345678"
        caller = "0000000000000000000000002222222222222222222222222222222222222222"
        raw = "0x" + selector + caller

        class Host:
            def load_abi(self, address, config):
                return [error_abi]

        output = (
            "LOWKEY_BREAK_FAMILY accounting\n"
            "SETUP_SUCCESS true\n"
            "FIRST_SUCCESS false\n"
            "SECOND_SUCCESS false\n"
            "FIRST_RETURNDATA_LENGTH 36\n"
            f"{raw}\n"
            "SECOND_RETURNDATA_LENGTH 36\n"
            f"{raw}\n"
            "TOTAL_TARGET_OUTFLOW 0\n"
            "LOWKEY_BREAK false\n"
        )
        result = break_engine._result_from_output(
            Host(),
            family="accounting",
            target=target,
            function="claim(uint256)",
            output=output,
            evidence_path="/tmp/evidence.json",
            config={"target": target.address},
        )
        self.assertEqual(result.status, "OBSERVED")
        self.assertIn("Unauthorized(address)", result.summary)
        self.assertIn("0x" + selector, result.detail["first_revert"])

    def test_result_parser_decodes_standard_error_string_without_abi(self):
        target = break_engine.Target("Vault", "0x" + "1" * 40)
        # ABI encoding of Error("not authorized").
        message = b"not authorized"
        payload = (
            (32).to_bytes(32, "big")
            + len(message).to_bytes(32, "big")
            + message
            + b"\x00" * (32 - len(message) % 32)
        )
        raw = "0x08c379a0" + payload.hex()

        class Host:
            def load_abi(self, address, config):
                return []

        output = (
            "LOWKEY_BREAK_FAMILY replay\n"
            "SETUP_SUCCESS true\n"
            "FIRST_SUCCESS false\n"
            "FIRST_RETURNDATA_LENGTH 100\n"
            f"{raw}\n"
            "SECOND_SUCCESS false\n"
            "SECOND_RETURNDATA_LENGTH 100\n"
            f"{raw}\n"
            "TOTAL_TARGET_OUTFLOW 0\n"
            "LOWKEY_BREAK false\n"
        )
        result = break_engine._result_from_output(
            Host(),
            family="replay",
            target=target,
            function="claim()",
            output=output,
            evidence_path="/tmp/evidence.json",
            config={"target": target.address},
        )
        self.assertIn("Error(string): not authorized", result.summary)

    def test_accounting_break_requires_entitlement_baseline(self):
        target = break_engine.Target("Tipjar", "0x" + "1" * 40)
        fn = {
            "name": "withdraw",
            "inputs": [{"name": "amount", "type": "uint256"}],
            "stateMutability": "nonpayable",
        }
        body = break_engine._render_repeat_test(
            target,
            fn,
            "withdraw(uint256)",
            ["1"],
            "0",
            "accounting",
            None,
            entitlement_signature=None,
        )
        self.assertIn("console2.log(\"LOWKEY_BREAK\", false);", body)

    def test_result_parser_requires_explicit_break_marker(self):
        target = break_engine.Target("Tipjar", "0x" + "1" * 40)
        observed = break_engine._result_from_output(
            type("Host", (), {})(),
            family="replay",
            target=target,
            function="withdraw()",
            output='LOWKEY_BREAK_FAMILY replay\nLOWKEY_BREAK false',
            evidence_path="/tmp/evidence.json",
        )
        self.assertEqual(observed.status, "OBSERVED")
        self.assertFalse(observed.break_condition)

        broken = break_engine._result_from_output(
            type("Host", (), {})(),
            family="replay",
            target=target,
            function="withdraw()",
            output='LOWKEY_BREAK_FAMILY replay\nLOWKEY_BREAK true',
            evidence_path="/tmp/evidence.json",
        )
        self.assertEqual(broken.status, "BREAK")
        self.assertTrue(broken.break_condition)


    def test_asset_getter_discovery_and_token_tracking_renderer(self):
        functions = [{
            "name": "stakeToken",
            "inputs": [],
            "outputs": [{"type": "address"}],
            "stateMutability": "view",
        }]
        self.assertEqual(
            break_engine._find_asset_getter_signature(functions),
            "stakeToken()",
        )
        target = break_engine.Target("ConfidencePool", "0x" + "1" * 40)
        fn = {"name": "withdraw", "inputs": [], "stateMutability": "nonpayable"}
        body = break_engine._render_repeat_test(
            target, fn, "withdraw()", [], "0", "accounting", "10ether",
            entitlement_signature="balances(address)",
            asset_signature="stakeToken()",
        )
        self.assertIn("deal(assetToken, ATTACKER, 1 ether)", body)
        self.assertIn("IERC20Lowkey(assetToken).balanceOf(ATTACKER)", body)
        self.assertIn('console2.log("TOTAL_ATTACKER_TOKEN_GAIN"', body)
        self.assertIn("assetReadOk && totalTokenGain > entitlementBefore", body)

    def test_result_parser_marks_invalid_setup_as_lab_issue(self):
        target = break_engine.Target("ConfidencePool", "0x" + "1" * 40)
        output = """LOWKEY_BREAK_FAMILY accounting
SETUP_SUCCESS false
SETUP_RETURNDATA_LENGTH 36
0x
"""
        result = break_engine._result_from_output(
            type("Host", (), {"tool_path": lambda self, name: name})(),
            family="accounting",
            target=target,
            function="withdraw()",
            output=output,
            evidence_path=None,
            config={},
        )
        self.assertEqual(result.status, "LAB_ISSUE")

    def test_result_parser_marks_failed_first_probe_as_blocked(self):
        target = break_engine.Target("ConfidencePool", "0x" + "1" * 40)
        output = """LOWKEY_BREAK_FAMILY accounting
FIRST_SUCCESS false
FIRST_RETURNDATA_LENGTH 0
SECOND_SUCCESS false
SECOND_RETURNDATA_LENGTH 0
"""
        result = break_engine._result_from_output(
            type("Host", (), {"tool_path": lambda self, name: name})(),
            family="accounting",
            target=target,
            function="withdraw()",
            output=output,
            evidence_path=None,
            config={},
        )
        self.assertEqual(result.status, "BLOCKED")


if __name__ == "__main__":
    unittest.main()
