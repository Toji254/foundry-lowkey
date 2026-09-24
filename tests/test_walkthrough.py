import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "walkthrough.py"


spec = importlib.util.spec_from_file_location("lowkey_walkthrough", MODULE)
walk = importlib.util.module_from_spec(spec)
assert spec.loader is not None
# Python 3.14's dataclasses resolves class annotations through sys.modules.
# Register the dynamically loaded module before executing it.
import sys
sys.modules[spec.name] = walk
spec.loader.exec_module(walk)


class WalkthroughTests(unittest.TestCase):
    def test_address_classifier_does_not_confuse_actor_names(self):
        self.assertTrue(walk._is_address("0x" + "1" * 40))
        self.assertFalse(walk._is_address("Alice"))
        self.assertFalse(walk._is_address("0x" + "1" * 39))

    def test_split_params_handles_arrays_and_tuples(self):
        items = walk._split_params(
            "address agreement, tuple(address,uint256) data, address[] accounts"
        )
        self.assertEqual(len(items), 3)
        self.assertEqual(items[0], "address agreement")
        self.assertIn("tuple(address,uint256)", items[1])
        self.assertEqual(items[2], "address[] accounts")

    def test_source_parser_ignores_comment_and_natspec_noise(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            src = root / "src"
            src.mkdir()
            (src / "Noise.sol").write_text(
                """
                /// natspec mentions foo.bar() and fake.member().
                import "src/libraries/PoolStates.sol";
                contract Noise {
                    // fake.commentCall()
                    address public token;
                    function use() external {
                        token.balanceOf(msg.sender);
                    }
                }
                """,
                encoding="utf-8",
            )
            contracts = walk._parse_solidity_sources(root)
            self.assertIn("Noise", contracts)
            edges = walk._system_edges([], { "Noise": contracts["Noise"].functions }, contracts)
            self.assertFalse(any(e["to"] == "natspec" for e in edges))
            self.assertFalse(any(e["to"] == "fake" for e in edges))
            self.assertTrue(any(e["to"] == "token" for e in edges))

    def test_source_parser_sees_typed_external_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            src = root / "src"
            src.mkdir()
            (src / "Factory.sol").write_text(
                """
                pragma solidity ^0.8.20;
                interface IAgreement { function owner() external view returns(address); }
                contract Factory {
                    address agreement;
                    function create(address a) external {
                        IAgreement(a).owner();
                    }
                }
                """,
                encoding="utf-8",
            )
            contracts = walk._parse_solidity_sources(root)
            factory = contracts["Factory"]
            create = next(x for x in factory.functions if x.name == "create")
            self.assertTrue(
                any(
                    c.get("kind") == "typed-call"
                    and c.get("interface") == "IAgreement"
                    and c.get("function") == "owner"
                    for c in create.calls
                )
            )

    def test_scope_accounts_falls_back_to_live_account_membership(self):
        class Stub:
            def __init__(self):
                self.calls = []
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            agreement = "0x" + "1" * 40
            alice = "0x" + "a" * 40
            bob = "0x" + "b" * 40
            funcs = [
                walk.FunctionInfo(
                    contract="Agreement",
                    name="isContractInScope",
                    inputs=[{"type": "address", "name": "contractAddress"}],
                    outputs=[{"type": "bool", "name": ""}],
                    mutability="view",
                    signature="isContractInScope(address)",
                )
            ]

            responses = {
                alice.lower(): "true",
                bob.lower(): "false",
            }

            def fake_query(_root, _rpc, _address, _sig, args, _caller=None):
                return 0, responses[args[0].lower()], ""

            with patch.object(walk, "_eth_accounts", return_value=[alice, bob]):
                with patch.object(walk, "_query_by_signature", side_effect=fake_query):
                    with patch.object(walk, "_code_size", return_value=100):
                        result = walk._scope_accounts(root, "http://127.0.0.1:8545", agreement, funcs)

            self.assertEqual(result, [alice])

    def test_factory_does_not_synthesize_actors_as_create_pool_contract_roles(self):
        node = walk.LiveNode(
            address="0x" + "1" * 40,
            name="ConfidencePoolFactory",
            code_size=100,
            artifact_contract="ConfidencePoolFactory",
        )
        fn = walk.FunctionInfo(
            contract="ConfidencePoolFactory",
            name="createPool",
            inputs=[
                {"type": "address", "name": "agreement"},
                {"type": "address", "name": "stakeToken"},
                {"type": "uint256", "name": "expiry"},
                {"type": "uint256", "name": "minStake"},
                {"type": "address", "name": "recoveryAddress"},
                {"type": "address[]", "name": "accounts"},
            ],
            outputs=[],
            mutability="nonpayable",
            signature="createPool(address,address,uint256,uint256,address,address[])",
        )
        args, reason = walk._semantic_args(
            node,
            fn,
            {"ConfidencePoolFactory": [fn]},
            [node],
            {"Alice": "0x" + "a" * 40, "Bob": "0x" + "b" * 40},
            {},
            1_800_000_000,
            pathlib.Path(tmp := "."),
            "http://127.0.0.1:8545",
        )
        self.assertIsNone(args)
        self.assertIn("agreement", reason.lower())

    def test_bootstrap_discovery_is_protocol_agnostic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            script_dir = root / "script"
            test_dir = root / "test"
            script_dir.mkdir()
            test_dir.mkdir()

            (script_dir / "Deploy.s.sol").write_text(
                """
                contract Deploy {
                    function run() external {
                        vm.startBroadcast();
                        new Example();
                    }
                }
                """,
                encoding="utf-8",
            )
            (test_dir / "Example.t.sol").write_text(
                """
                contract ExampleTest {
                    function setUp() public { new Example(); }
                }
                """,
                encoding="utf-8",
            )

            with patch.object(walk, "_code_size", return_value=0):
                result = walk._discover_bootstrap(root, "http://127.0.0.1:8545")

            self.assertEqual(result["scripts"][0]["path"], "script/Deploy.s.sol")
            self.assertIn("broadcast", result["scripts"][0]["signals"])
            self.assertIn("contract creation", result["scripts"][0]["signals"])
            self.assertEqual(result["tests"][0]["path"], "test/Example.t.sol")
            self.assertIn("setUp()", result["tests"][0]["signals"])

    def test_offline_configured_target_does_not_hide_live_broadcast(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            configured = "0x" + "1" * 40
            live = "0x" + "2" * 40
            bootstrap = {
                "audit_targets": [],
                "audit_evidence": [],
                "live_deployments": [
                    {
                        "address": live,
                        "contract": "Example",
                        "broadcast": "broadcast/Deploy/31337/run-latest.json",
                        "index": 1,
                    }
                ],
            }
            with patch.object(
                walk, "_code_size",
                side_effect=lambda _rpc, addr: 100 if addr.lower() == live.lower() else 0,
            ):
                target, source = walk._resolve_walkthrough_target(
                    root,
                    {"target": configured, "targets": {}},
                    "http://127.0.0.1:8545",
                    bootstrap,
                )
            self.assertEqual(target, live)
            self.assertTrue(source.startswith("broadcast "))

    def test_cmd_returns_process_output_and_exit_code(self):
        code, stdout, stderr = walk._cmd(
            [sys.executable, "-c", "print('walkthrough-ok'); raise SystemExit(7)"],
            timeout=10,
        )
        self.assertEqual(code, 7)
        self.assertEqual(stdout.strip(), "walkthrough-ok")
        self.assertEqual(stderr, "")

    def test_discovery_ignores_dry_run_deployment_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            dry = root / "broadcast" / "Setup.s.sol" / "31337" / "dry-run"
            live = root / "broadcast" / "Setup.s.sol" / "31337"
            dry.mkdir(parents=True)
            live.mkdir(parents=True)
            payload = {"transactions": [{"contractAddress": "0x" + "1" * 40, "contractName": "Fake"}]}
            (dry / "run-latest.json").write_text(json.dumps(payload), encoding="utf-8")
            payload2 = {"transactions": [{"contractAddress": "0x" + "2" * 40, "contractName": "Real"}]}
            (live / "run-latest.json").write_text(json.dumps(payload2), encoding="utf-8")
            with patch.object(walk, "_code_size", return_value=100):
                result = walk._discover_bootstrap(root, "http://127.0.0.1:8545")
            self.assertEqual(len(result["deployments"]), 1)
            self.assertEqual(result["deployments"][0]["contract"], "Real")

    def test_target_prefers_current_broadcast_identity_over_stale_address(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            stale = "0x" + "1" * 40
            current = "0x" + "2" * 40
            bootstrap = {
                "audit_targets": [{"target": stale, "file": "audit_start.json"}],
                "audit_evidence": [],
                "live_deployments": [{
                    "address": current,
                    "contract": "ConfidencePoolFactory",
                    "broadcast": "broadcast/LocalSetup.s.sol/31337/run-latest.json",
                    "index": 6,
                }],
            }
            with patch.object(walk, "_code_size", return_value=100):
                target, source = walk._resolve_walkthrough_target(
                    root,
                    {"target": stale, "target_contract": "ConfidencePoolFactory", "targets": {}},
                    "http://127.0.0.1:8545",
                    bootstrap,
                )
            self.assertEqual(target, current)
            self.assertIn("current broadcast deployment", source)

    def test_human_error_explains_and_recommends(self):
        message, recommendation = walk._friendly_error("StakeTokenNotAllowed()", "")
        self.assertIn("not currently approved", message)
        self.assertIn("approve the token", recommendation)

    def test_render_story_explains_steps_and_hides_import_noise(self):
        node = walk.LiveNode(
            address="0x" + "1" * 40,
            name="ConfidencePoolFactory",
            code_size=100,
            artifact_contract="ConfidencePoolFactory",
        )
        fn = walk.FunctionInfo(
            contract="ConfidencePoolFactory",
            name="createPool",
            inputs=[],
            outputs=[],
            mutability="nonpayable",
            signature="createPool()",
            source=None,
            line=None,
        )
        action = {
            "node": node,
            "function": fn,
            "args": [],
            "caller": "0x" + "a" * 40,
            "actor_name": "Alice",
            "status": "BLOCKED",
            "phase": "CREATE",
            "what": "Create a new pool.",
            "why": "This is the main bridge into a new pool.",
            "result": {"ok": False, "decoded_error": "StakeTokenNotAllowed()", "raw": ""},
            "diagnosis": [],
        }
        contracts = {
            "ConfidencePoolFactory": walk.ContractInfo(
                name="ConfidencePoolFactory", source="src/Factory.sol", line=1, kind="contract",
                imports=["openzeppelin/contracts/access/Ownable.sol"], functions=[fn]
            )
        }
        rendered = walk._render_story(
            pathlib.Path("."), [node], {"ConfidencePoolFactory": [fn]}, contracts,
            [action], {"Alice": "0x" + "a" * 40}, None, False,
            {"target": node.address, "bootstrap": {}, "static_system": {}, "system_manifest": {},}
        )
        self.assertIn("SYSTEM IN PLAIN ENGLISH", rendered)
        self.assertIn("CONNECTIONS", rendered)
        self.assertIn("WHAT", rendered)
        self.assertIn("WHY", rendered)
        self.assertIn("NEXT", rendered)
        self.assertNotIn("import", rendered.lower())

    def test_auto_bootstrap_uses_only_safe_local_setup_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            script = root / "script"
            script.mkdir()
            (script / "LocalSetup.s.sol").write_text(
                """
                contract LocalSetup {
                    function run() external {
                        vm.startBroadcast();
                        new Example();
                    }
                }
                """,
                encoding="utf-8",
            )
            poc = root / "script" / "Exploit.s.sol"
            poc.write_text(
                """
                contract Exploit {
                    function run() external { vm.startBroadcast(); new Example(); }
                }
                """,
                encoding="utf-8",
            )
            calls = []

            def fake_cmd(args, cwd=None, timeout=30):
                calls.append((args, timeout))
                return 0, "", ""

            with patch.object(walk, "_is_local_rpc", return_value=True):
                with patch.object(walk, "_eth_accounts", return_value=[]):
                    with patch.object(walk, "_cmd", side_effect=fake_cmd):
                        ok, reason = walk._auto_bootstrap_local(
                            root,
                            {"rpc": "http://127.0.0.1:8545"},
                            {
                                "scripts": [
                                    {
                                        "path": "script/Exploit.s.sol",
                                        "signals": ["run()", "broadcast", "contract creation"],
                                    },
                                    {
                                        "path": "script/LocalSetup.s.sol",
                                        "signals": ["run()", "broadcast", "contract creation"],
                                    },
                                ]
                            },
                        )
            self.assertTrue(ok)
            self.assertIn("LocalSetup.s.sol", reason)
            self.assertEqual(len(calls), 2)
            self.assertNotIn("Exploit.s.sol", " ".join(calls[0][0]))

    def test_walkthrough_target_prefers_live_config_then_audit_evidence_then_broadcast(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            configured = "0x" + "1" * 40
            evidenced = "0x" + "2" * 40
            broadcasted = "0x" + "3" * 40
            bootstrap = {
                "audit_evidence": [
                    {"file": ".audit/evidence/context.json", "target": evidenced},
                    {"file": ".audit/evidence/audit_start.json", "target": evidenced},
                ],
                "audit_targets": [
                    {"target": evidenced, "file": "audit_start.json"},
                ],
                "live_deployments": [
                    {
                        "address": broadcasted,
                        "contract": "Example",
                        "broadcast": "broadcast/Deploy/31337/run-latest.json",
                        "index": 1,
                    }
                ],
            }

            sizes = {
                configured.lower(): 100,
                evidenced.lower(): 100,
                broadcasted.lower(): 100,
            }

            with patch.object(
                walk, "_code_size", side_effect=lambda _rpc, addr: sizes.get(addr.lower(), 0)
            ):
                target, source = walk._resolve_walkthrough_target(
                    root,
                    {"target": configured, "targets": {}},
                    "http://127.0.0.1:8545",
                    bootstrap,
                )
            self.assertEqual(target, configured)
            self.assertEqual(source, "configured target")

            with patch.object(walk, "_code_size", return_value=100):
                target, source = walk._resolve_walkthrough_target(
                    root,
                    {"target": None, "targets": {}},
                    "http://127.0.0.1:8545",
                    bootstrap,
                )
            self.assertEqual(target, evidenced)
            self.assertEqual(source, "audit evidence 'audit_start.json'")

            with patch.object(
                walk, "_code_size",
                side_effect=lambda _rpc, addr: 100 if addr.lower() == broadcasted.lower() else 0,
            ):
                target, source = walk._resolve_walkthrough_target(
                    root,
                    {"target": None, "targets": {}},
                    "http://127.0.0.1:8545",
                    {"audit_evidence": [], "live_deployments": bootstrap["live_deployments"]},
                )
            self.assertEqual(target, broadcasted)
            self.assertTrue(source.startswith("broadcast "))

    def test_stale_audit_target_does_not_override_live_broadcast(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            stale = "0x" + "1" * 40
            live = "0x" + "2" * 40
            bootstrap = {
                "audit_targets": [
                    {"target": stale, "file": "audit_start.json"},
                ],
                "audit_evidence": [],
                "live_deployments": [
                    {
                        "address": live,
                        "contract": "Example",
                        "broadcast": "broadcast/Deploy/31337/run-latest.json",
                        "index": 1,
                    }
                ],
            }
            with patch.object(
                walk, "_code_size",
                side_effect=lambda _rpc, addr: 100 if addr.lower() == live.lower() else 0,
            ):
                target, source = walk._resolve_walkthrough_target(
                    root,
                    {"target": None, "targets": {}},
                    "http://127.0.0.1:8545",
                    bootstrap,
                )
            self.assertEqual(target, live)
            self.assertTrue(source.startswith("broadcast "))

    def test_static_system_context_uses_setup_deployments(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source_dir = root / "src"
            source_dir.mkdir()
            (source_dir / "Factory.sol").write_text(
                "contract Factory {}",
                encoding="utf-8",
            )
            contracts = {
                "Factory": walk.ContractInfo(
                    name="Factory",
                    source="src/Factory.sol",
                    line=1,
                    kind="contract",
                )
            }
            bootstrap = {
                "initialization": [
                    {"source": "script/Deploy.s.sol", "line": 10, "kind": "deploy", "target": "Factory"},
                    {"source": "script/Deploy.s.sol", "line": 11, "kind": "configuration", "target": "setAllowed"},
                ]
            }
            view = walk._static_system_context(bootstrap, contracts)
            self.assertEqual(view["deployed_contracts"], ["Factory"])
            self.assertEqual(view["project_contracts"], ["Factory"])
            self.assertEqual(len(view["script_flow"]["script/Deploy.s.sol"]), 2)

    def test_render_story_consumes_model_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            meta = {
                "bootstrap": {
                    "initialization": [
                        {"source": "script/Deploy.s.sol", "line": 10, "kind": "deploy", "target": "Example"}
                    ],
                    "roles": [],
                    "adversarial": [],
                    "audit_evidence": [{"file": ".audit/evidence/context.json"}],
                },
                "system_manifest": {"schema": "lowkey.system-bootstrap.v1"},
            }
            rendered = walk._render_story(
                root,
                [],
                {},
                {},
                [],
                {},
                None,
                True,
                meta,
            )
            self.assertIn("BOOTSTRAP EVIDENCE", rendered)
            self.assertIn("initialization steps observed: 1", rendered)
            self.assertIn(".audit/evidence/context.json", rendered)

    def test_extract_audit_targets_prefers_canonical_evidence(self):
        target = "0x" + "1" * 40
        other = "0x" + "2" * 40
        evidence = [
            {"file": ".audit/evidence/context.json", "target": target},
            {"file": ".audit/evidence/audit_start.json", "target": target},
            {"file": ".audit/evidence/risk.json", "target": other},
        ]
        result = walk._extract_audit_targets(evidence)
        self.assertEqual(result[0], {"target": target, "file": "audit_start.json"})
        self.assertEqual(result[1], {"target": other, "file": "risk.json"})

    def test_walkthrough_target_retains_persisted_evidence_without_live_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            target = "0x" + "1" * 40
            bootstrap = {
                "audit_targets": [
                    {"target": target, "file": "audit_start.json"},
                ],
                "audit_evidence": [],
                "live_deployments": [],
            }
            with patch.object(walk, "_code_size", return_value=0):
                resolved, source = walk._resolve_walkthrough_target(
                    root,
                    {"target": None, "targets": {}},
                    "http://127.0.0.1:8545",
                    bootstrap,
                )
            self.assertEqual(resolved, target)
            self.assertEqual(source, "audit evidence 'audit_start.json' (no live bytecode)")

    def test_walkthrough_target_is_safe_when_nothing_is_discovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with patch.object(walk, "_code_size", return_value=0):
                target, source = walk._resolve_walkthrough_target(
                    root,
                    {"target": None, "targets": {}},
                    "http://127.0.0.1:8545",
                    {"audit_evidence": [], "audit_targets": [], "live_deployments": []},
                )
            self.assertIsNone(target)
            self.assertEqual(source, "not discovered")
            self.assertEqual(walk._target_label({}, target), "Target")

    def test_error_decoder_reports_static_custom_error(self):
        err = {"name": "StakingClosed", "inputs": []}
        selector = walk._keccak_selector("StakingClosed()")
        decoded = walk._decode_error(selector, [err])
        self.assertEqual(decoded, "StakingClosed()")

    def test_trace_revert_frames_walk_nested_calls(self):
        trace = {
            "to": "0x" + "1" * 40,
            "calls": [
                {
                    "to": "0x" + "2" * 40,
                    "error": "execution reverted",
                    "revertReason": "StakeTokenNotAllowed()",
                }
            ],
        }
        frames = walk._trace_revert_frames(trace)
        self.assertEqual(len(frames), 1)
        self.assertIn("StakeTokenNotAllowed()", frames[0])

    def test_mutations_include_zero_and_actor_swaps(self):
        actors = {
            "Alice": "0x" + "a" * 40,
            "Bob": "0x" + "b" * 40,
            "Attacker": "0x" + "c" * 40,
        }
        mutations = walk._mutations(1, "uint256", actors, __import__("random").Random(1337))
        self.assertIn(0, mutations)
        self.assertIn(2, mutations)

        addr_mutations = walk._mutations(
            actors["Alice"], "address", actors, __import__("random").Random(1337)
        )
        self.assertIn(actors["Bob"], addr_mutations)
        self.assertIn(walk.ZERO, addr_mutations)


if __name__ == "__main__":
    unittest.main()
