import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "break_engine.py"
PLAYBOOK = ROOT / "lowkey" / "break_playbook.py"

playbook_spec = importlib.util.spec_from_file_location("lowkey_break_playbook", PLAYBOOK)
playbook = importlib.util.module_from_spec(playbook_spec)
playbook_spec.loader.exec_module(playbook)

spec = importlib.util.spec_from_file_location("lowkey_break_engine", MODULE)
break_engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(break_engine)


class BreakEngineTests(unittest.TestCase):
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
        self.assertIn("address(uint160(0x00BEEF000000000000000000000000000000000042))", body)
        self.assertNotIn("address(0x5fbdb2315678afecb367f032d93f642f64180aa3)", body)
        funded = break_engine._render_reentrancy_test(
            target, fn, "withdraw()", [], 3, seed_fund="10 ether"
        )
        self.assertIn("vm.deal(TARGET, 10 ether);", funded)
        self.assertIn("call{value: 10 ether}", funded)


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


if __name__ == "__main__":
    unittest.main()
