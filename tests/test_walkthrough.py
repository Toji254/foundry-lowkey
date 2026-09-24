import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "walkthrough.py"

spec = importlib.util.spec_from_file_location("walkthrough", MODULE)
walkthrough = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = walkthrough
spec.loader.exec_module(walkthrough)


class WalkthroughTests(unittest.TestCase):

    def test_cli_arg_lowercases_booleans(self):
        self.assertEqual(walkthrough._cli_arg(True), "true")
        self.assertEqual(walkthrough._cli_arg(False), "false")

    def test_confidence_pool_recipe_contains_lifecycle(self):
        config={
            "target":"0x"+"1"*40,
            "_walkthrough_recipe":"confidence-pool",
            "lab_system":{
                "pool":"0x"+"1"*40,
                "stake_token":"0x"+"2"*40,
                "attack_registry":"0x"+"3"*40,
                "moderator":"0x"+"4"*40,
            },
        }
        actors=[
            walkthrough.Actor("Alice","0x"+"a"*40,0),
            walkthrough.Actor("Bob","0x"+"b"*40,1),
        ]
        recipe=walkthrough._confidence_pool_recipe(config,actors)
        names=[s.function for s in recipe]
        self.assertIn("contributeBonus(uint256)",names)
        self.assertIn("stake(uint256)",names)
        self.assertIn("pokeRiskWindow()",names)
        self.assertIn("flagSurvived(address)",names)
        self.assertIn("claimSurvived()",names)

    def test_struct_mapping_and_functions_are_modelled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "out" / "Demo.sol").mkdir(parents=True)
            (root / "src" / "Demo.sol").write_text(
                """
                pragma solidity ^0.8.20;
                contract Demo {
                    struct Position { address owner; uint256 amount; }
                    mapping(address => Position) public positions;
                    uint256[] public ids;
                    modifier onlyOwner() { _; }
                    event Deposited(address indexed user, uint256 amount);
                    function deposit(uint256 amount) external payable { positions[msg.sender].amount += amount; }
                    function withdraw(uint256 amount) external { positions[msg.sender].amount -= amount; }
                }
                """,
                encoding="utf-8",
            )
            artifact = {
                "contractName": "Demo",
                "sourceName": "src/Demo.sol",
                "abi": [
                    {"type": "function", "name": "deposit", "stateMutability": "payable",
                     "inputs": [{"name": "amount", "type": "uint256"}], "outputs": []},
                    {"type": "function", "name": "withdraw", "stateMutability": "nonpayable",
                     "inputs": [{"name": "amount", "type": "uint256"}], "outputs": []},
                    {"type": "event", "name": "Deposited", "inputs": []},
                ],
                "storageLayout": {"storage": [], "types": {}},
            }
            (root / "out" / "Demo.sol" / "Demo.json").write_text(json.dumps(artifact), encoding="utf-8")
            models = walkthrough._artifact_models(root)
        self.assertEqual(len(models), 1)
        model = models[0]
        self.assertIn("deposit(uint256)", model.functions)
        self.assertIn("withdraw(uint256)", model.functions)
        self.assertIn("Position", model.structs)
        self.assertEqual(model.structs["Position"][0].name, "owner")
        self.assertEqual(model.mappings[0]["name"], "positions")
        self.assertEqual(model.arrays[0]["name"], "ids")
        self.assertIn("onlyOwner", model.modifiers)


    def test_artifacts_are_scoped_to_project_source_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")
            entries = [
                ("src/App.sol", "App"),
                ("lib/Dependency.sol", "Dependency"),
                ("test/AppTest.t.sol", "AppTest"),
            ]
            for source, name in entries:
                source_path = root / source
                source_path.parent.mkdir(parents=True, exist_ok=True)
                source_path.write_text(
                    f"pragma solidity ^0.8.20; contract {name} {{ function ping() external {{}} }}",
                    encoding="utf-8",
                )
                out = root / "out" / (pathlib.Path(source).stem + ".sol")
                out.mkdir(parents=True, exist_ok=True)
                (out / f"{name}.json").write_text(
                    json.dumps({
                        "contractName": name,
                        "sourceName": source,
                        "abi": [{"type": "function", "name": "ping", "stateMutability": "nonpayable", "inputs": [], "outputs": []}],
                    }),
                    encoding="utf-8",
                )
            models = walkthrough._artifact_models(root)
        self.assertEqual([model.name for model in models], ["App"])

    def test_artifact_source_path_fallback_handles_missing_source_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")
            (root / "src" / "Fixture.sol").write_text(
                "pragma solidity ^0.8.20; contract Fixture { function ping() external {} }",
                encoding="utf-8",
            )
            out = root / "out" / "Fixture.sol"
            out.mkdir(parents=True)
            (out / "Fixture.json").write_text(
                json.dumps({
                    "contractName": "Fixture",
                    "abi": [{"type": "function", "name": "ping", "stateMutability": "nonpayable", "inputs": [], "outputs": []}],
                }),
                encoding="utf-8",
            )
            models = walkthrough._artifact_models(root)
        self.assertEqual([model.name for model in models], ["Fixture"])
        self.assertEqual(models[0].source, "src/Fixture.sol")

    def test_planner_excludes_setup_and_admin_controls(self):
        model = walkthrough.ContractModel(
            name="Factory",
            source="src/Factory.sol",
            artifact="out/Factory.sol/Factory.json",
            abi=[
                {"type": "function", "name": "initialize", "stateMutability": "nonpayable", "inputs": []},
                {"type": "function", "name": "acceptOwnership", "stateMutability": "nonpayable", "inputs": []},
                {"type": "function", "name": "pause", "stateMutability": "nonpayable", "inputs": []},
                {"type": "function", "name": "createPool", "stateMutability": "nonpayable", "inputs": []},
            ],
        )
        actors = [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)]
        steps = walkthrough.plan_workflow(model, actors, actors[0].address, 100, 8)
        self.assertEqual([step.function for step in steps], ["createPool()"])

    def test_runtime_discovery_marks_clones_as_live_contracts(self):
        child = walkthrough.ContractModel(
            name="Child",
            source="src/Child.sol",
            artifact="out/Child.sol/Child.json",
        )
        known = [walkthrough.RuntimeContract("0x" + "1" * 40, "Factory", "Factory", "target")]
        trace = {"type": "CREATE2", "from": "0x" + "1" * 40, "result": "0x" + "3" * 40}
        with patch.object(walkthrough, "_runtime_code", return_value="0x1234"),              patch.object(walkthrough, "_match_runtime_model", return_value=("Child", "0x" + "2" * 40)):
            found = walkthrough._discover_runtime_contracts(
                pathlib.Path("."),
                "http://127.0.0.1:8545",
                [child],
                known,
                None,
                trace,
                1,
                "0x" + "1" * 40,
            )
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].model, "Child")
        self.assertEqual(found[0].relation, "CLONE")
        self.assertEqual(found[0].parent, "0x" + "1" * 40)

    def test_runtime_graph_shows_parent_child_relation(self):
        runtime = [
            walkthrough.RuntimeContract("0x" + "1" * 40, "Factory", "Factory", "target"),
            walkthrough.RuntimeContract(
                "0x" + "2" * 40,
                "Pool",
                "Pool #1",
                "CLONE",
                "0x" + "1" * 40,
                1,
                "0x" + "3" * 40,
            ),
        ]
        rendered = walkthrough._render_runtime_graph(runtime, enabled=False)
        self.assertIn("Factory", rendered)
        self.assertIn("Pool #1", rendered)
        self.assertIn("⋯⋯⋯▶", rendered)

    def test_argument_inference_uses_protocol_expiry_window(self):
        actors = [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)]
        self.assertEqual(
            walkthrough._arg_for({"name": "expiry", "type": "uint256"}, actors, actors[0].address, 100),
            100 + 31 * 24 * 60 * 60,
        )

    def test_role_aware_actor_selection_uses_moderator(self):
        actors = [
            walkthrough.Actor("Alice", "0x" + "1" * 40, 0),
            walkthrough.Actor("Bob", "0x" + "2" * 40, 1),
        ]
        observed = {"defaultoutcomemoderator": actors[1].address}
        self.assertEqual(
            walkthrough._actor_for_function("flagOutcome", actors, observed).name,
            "Bob",
        )

    def test_argument_inference_uses_roles(self):
        actors = [
            walkthrough.Actor("Alice", "0x" + "1" * 40, 0),
            walkthrough.Actor("Bob", "0x" + "2" * 40, 1),
            walkthrough.Actor("Attacker", "0x" + "3" * 40, 2),
        ]
        self.assertEqual(
            walkthrough._arg_for({"name": "recipient", "type": "address"}, actors, actors[0].address, 100),
            actors[1].address,
        )
        self.assertEqual(
            walkthrough._arg_for({"name": "attacker", "type": "address"}, actors, actors[0].address, 100),
            actors[2].address,
        )
        self.assertEqual(
            walkthrough._arg_for({"name": "deadline", "type": "uint256"}, actors, actors[0].address, 100),
            3700,
        )

    def test_phase_order_puts_flag_before_claims(self):
        self.assertLess(
            walkthrough._phase_score("flagOutcome")[0],
            walkthrough._phase_score("claimAttackerBounty")[0],
        )
        self.assertLess(
            walkthrough._phase_score("flagOutcome")[1],
            walkthrough._phase_score("claimAttackerBounty")[1],
        )

    def test_planner_covers_multiple_phases(self):
        model = walkthrough.ContractModel(
            name="Pool",
            source="src/Pool.sol",
            artifact="out/Pool.sol/Pool.json",
            abi=[
                {"type": "function", "name": "create", "stateMutability": "nonpayable", "inputs": []},
                {"type": "function", "name": "deposit", "stateMutability": "payable", "inputs": []},
                {"type": "function", "name": "withdraw", "stateMutability": "nonpayable", "inputs": []},
                {"type": "function", "name": "pause", "stateMutability": "nonpayable", "inputs": []},
            ],
        )
        actors = [
            walkthrough.Actor("Alice", "0x" + "1" * 40, 0),
            walkthrough.Actor("Bob", "0x" + "2" * 40, 1),
        ]
        steps = walkthrough.plan_workflow(model, actors, actors[0].address, 100, 8)
        self.assertGreaterEqual(len(steps), 2)
        self.assertNotIn("pause()", [s.function for s in steps])
        self.assertEqual(steps[0].function, "create()")
        self.assertEqual(steps[1].function, "deposit()")

    def test_source_call_edges_are_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "out" / "Demo.sol").mkdir(parents=True)
            (root / "src" / "Demo.sol").write_text(
                """
                pragma solidity ^0.8.20;
                contract Demo {
                    function start() external { finish(1); }
                    function finish(uint256 value) internal {}
                }
                """,
                encoding="utf-8",
            )
            artifact = {
                "contractName": "Demo",
                "sourceName": "src/Demo.sol",
                "abi": [
                    {"type": "function", "name": "start", "stateMutability": "nonpayable",
                     "inputs": [], "outputs": []},
                    {"type": "function", "name": "finish", "stateMutability": "internal",
                     "inputs": [{"name": "value", "type": "uint256"}], "outputs": []},
                ],
            }
            (root / "out" / "Demo.sol" / "Demo.json").write_text(json.dumps(artifact), encoding="utf-8")
            model = walkthrough._artifact_models(root)[0]
        self.assertTrue(any(
            edge["from"] == "start" and edge["to_function"] == "finish(uint256)"
            for edge in model.calls
        ))

    def test_friendly_renderer_has_no_host_dependency(self):
        actors = [
            walkthrough.Actor("Alice", "0x" + "1" * 40, 0),
            walkthrough.Actor("Bob", "0x" + "2" * 40, 1),
        ]
        self.assertEqual(walkthrough._friendly_arg(actors[0].address, actors), "Alice")
        self.assertEqual(walkthrough._friendly_arg(True, actors), "true")
        self.assertEqual(walkthrough._friendly_arg(False, actors), "false")

    def test_protocol_story_connects_steps_with_arrows(self):
        actors = [
            walkthrough.Actor("Alice", "0x" + "1" * 40, 0),
            walkthrough.Actor("Bob", "0x" + "2" * 40, 1),
        ]
        steps = [
            walkthrough.Step(
                1, "Alice", "Pool", "0x" + "3" * 40,
                "deposit()", [], value_wei=10**18, status="success",
            ),
            walkthrough.Step(
                2, "Bob", "Pool", "0x" + "3" * 40,
                "withdraw()", [], status="planned",
            ),
        ]
        rendered = walkthrough._render_protocol_story(steps, steps[1], actors, enabled=False)
        self.assertIn("Alice ────▶ Pool.deposit()", rendered)
        self.assertIn("1 ETH", rendered)
        self.assertIn("▼", rendered)
        self.assertIn("Bob ────▶ Pool.withdraw()", rendered)
        self.assertIn("◀ LIVE", rendered)

    def test_cli_arg_normalizes_bool_and_arrays(self):
        self.assertEqual(walkthrough._cli_arg(True), "true")
        self.assertEqual(walkthrough._cli_arg(False), "false")
        self.assertEqual(
            walkthrough._cli_arg(["0x" + "1" * 40, "0x" + "2" * 40]),
            "[0x" + "1" * 40 + ",0x" + "2" * 40 + "]",
        )

    def test_confidence_pool_recipe_uses_correct_registry_ordinals(self):
        config = {
            "target": "0x" + "1" * 40,
            "_walkthrough_recipe": "confidence-pool",
            "lab_system": {
                "pool": "0x" + "1" * 40,
                "stake_token": "0x" + "2" * 40,
                "attack_registry": "0x" + "3" * 40,
                "moderator": "0x" + "4" * 40,
            },
        }
        actors = [
            walkthrough.Actor("Alice", "0x" + "a" * 40, 0),
            walkthrough.Actor("Bob", "0x" + "b" * 40, 1),
        ]
        recipe = walkthrough._confidence_pool_recipe(config, actors)
        state_updates = {
            s.args[0]: s.reason
            for s in recipe
            if s.function == "setAgreementState(uint8)"
        }
        self.assertEqual(state_updates[3], "LAB CONTROL: agreement enters UNDER_ATTACK")
        self.assertEqual(state_updates[5], "LAB CONTROL: agreement reaches PRODUCTION")

    def test_failure_explainer_is_plain_english(self):
        step = walkthrough.Step(1, "Alice", "Pool", "0x" + "3"*40, "stake(uint256)", [1], status="blocked")
        self.assertIn("staking deadline",
                      walkthrough._explain_failure(step, "execution reverted: StakingClosed", "Alice"))
        self.assertIn("not the configured outcome moderator",
                      walkthrough._explain_failure(step, "execution reverted: NotModerator", "Alice"))

    def test_protocol_flow_connects_steps_and_explains_failure(self):
        actors=[walkthrough.Actor("Alice","0x"+"1"*40,0), walkthrough.Actor("Bob","0x"+"2"*40,1)]
        bad=walkthrough.Step(1,"Alice","Pool","0x"+"3"*40,"stake(uint256)",[1],status="blocked",
                             error="PRECONDITION BLOCKED: execution reverted: StakingClosed")
        bad.error_reason=walkthrough._explain_failure(bad,bad.error,bad.actor)
        good=walkthrough.Step(2,"Bob","Pool","0x"+"3"*40,"withdraw()",[],status="success")
        rendered=walkthrough._render_protocol_story([bad,good],good,actors,False)
        self.assertIn("WHY IT FAILED",rendered)
        self.assertIn("staking deadline",rendered)
        self.assertIn("▼",rendered)
        self.assertIn("◀ NOW",rendered)

    def test_token_balance_lines_show_real_deltas(self):
        actor=walkthrough.Actor("Alice","0x"+"1"*40,0)
        step=walkthrough.Step(1,"Alice","Pool","0x"+"2"*40,"stake(uint256)",[1],status="success")
        step.token_balance_before={actor.address.lower():10}
        step.token_balance_after={actor.address.lower():9}
        self.assertIn("STAKE BALANCE Alice: -1",
                      walkthrough._friendly_token_balance_lines(step,[actor]))

    def test_auto_walkthrough_does_not_resurrect_stale_config_target(self):
        config = {
            "target": "0x" + "9" * 40,
            "target_contract": "ConfidencePool",
            "rpc": "http://127.0.0.1:8545",
        }

        class Host:
            def anvil_rpc_info(self, _config):
                return {"url": "http://127.0.0.1:8545", "accounts": ["0x" + "1" * 40]}

            def _bind_detected_anvil(self, _info):
                return None

            def _bootstrap_audit_target(self, _config, _root, allow_deploy=True):
                return None

        target, _ = walkthrough._target_from_host(
            Host(), config, pathlib.Path("."), None, True
        )
        self.assertIsNone(target)

    def test_live_path_renders_connected_interactions(self):
        steps = [
            walkthrough.Step(1, "Alice", "Factory", "0x" + "1" * 40,
                              "createPool(address,address,uint256,uint256,address,address[])", 
                              ["0x" + "2" * 40, "0x" + "3" * 40, 100, 1, "0x" + "4" * 40, ["0x" + "5" * 40]],
                              status="success"),
        ]
        rendered = walkthrough._render_live_path(steps, [], enabled=False)
        self.assertIn("Alice", rendered)
        self.assertIn("createPool", rendered)
        self.assertIn("───▶", rendered)
        self.assertIn("✓", rendered)

    def test_visual_renderer_has_distinct_protocol_shapes(self):
        storage = [
            {
                "label": "balances",
                "slot": "0",
                "type": "mapping(address => uint256)",
                "encoding": "mapping",
                "mapping": {
                    "key_type": "address",
                    "value_type": "uint256",
                    "rows": [{"key": "0x" + "1" * 40, "slot": "0xab", "value": 7}],
                },
            },
            {
                "label": "position",
                "slot": "1",
                "type": "Position",
                "struct": {
                    "type": "Position",
                    "fields": [
                        {"name": "owner", "type": "address", "slot": "1", "value": "0x" + "1" * 40},
                        {"name": "amount", "type": "uint256", "slot": "2", "value": 7},
                    ],
                },
            },
        ]
        rendered = walkthrough._render_storage(storage, enabled=False)
        self.assertIn("▣ MAPPING balances", rendered)
        self.assertIn("▤ STRUCT Position", rendered)
        self.assertIn("→", rendered)

    def test_replay_script_contains_only_successful_steps(self):
        model = walkthrough.ContractModel(
            name="Demo",
            source="src/Demo.sol",
            artifact="out/Demo.sol/Demo.json",
        )
        good = walkthrough.Step(1, "Alice", "Demo", "0x" + "1" * 40, "ping(uint256)", [7], status="success")
        bad = walkthrough.Step(2, "Bob", "Demo", "0x" + "1" * 40, "bad()", [], status="reverted")
        with tempfile.TemporaryDirectory() as tmp:
            path = walkthrough._generate_replay_script(pathlib.Path(tmp), model, "0x" + "1" * 40, [good, bad])
            content = path.read_text(encoding="utf-8")
        self.assertIn("ping(uint256)", content)
        self.assertNotIn("bad()", content)
        self.assertIn('LOWKEY_ALICE_KEY', content)
        self.assertEqual(content.count("(bool ok_"), 1)

    def test_replay_script_uses_exact_calldata_and_valid_literals(self):
        model = walkthrough.ContractModel(
            name="Demo",
            source="src/Demo.sol",
            artifact="out/Demo.sol/Demo.json",
        )
        alice = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
        good = walkthrough.Step(
            1,
            "Alice",
            "Demo",
            alice,
            "set(bool,address)",
            [True, "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"],
            value_wei=10**18,
            calldata="0xabcdef",
            status="success",
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = walkthrough._generate_replay_script(pathlib.Path(tmp), model, "0x" + "1" * 40, [good])
            content = path.read_text(encoding="utf-8")
        self.assertIn("target_1 = address(uint160(0x70997970c51812dc3a010c7d01b50e0d17dc79c8));", content)
        self.assertIn('.call{value: 1000000000000000000}(hex"abcdef");', content)
        self.assertIn("bool ok_1", content)
        self.assertNotIn("bool ok, )", content)
        self.assertNotIn("0x70997970c51812dc3a010c7d01b50e0d17dc79c8", content.split("target_1 =", 1)[-1].split(";", 1)[0] if "target_1 =" in content else "")

    def test_live_interaction_graph_reads_like_a_protocol_story(self):
        actors = [
            walkthrough.Actor("Alice", "0x" + "1" * 40, 0),
            walkthrough.Actor("Bob", "0x" + "2" * 40, 1),
        ]
        step = walkthrough.Step(
            1,
            "Alice",
            "Escrow",
            "0x" + "3" * 40,
            "deposit(address)",
            ["0x" + "2" * 40],
            value_wei=10**18,
            status="success",
            reason="Alice funds the escrow for Bob",
            inferred=False,
        )
        step.balance_before = {
            actors[0].address.lower(): 10**18,
            actors[1].address.lower(): 0,
            step.address.lower(): 0,
        }
        step.balance_after = {
            actors[0].address.lower(): 0,
            actors[1].address.lower(): 10**18,
            step.address.lower(): 0,
        }
        rendered = walkthrough._render_interaction_graph(step, actors, False)
        self.assertIn("[Alice] ── CALL deposit(Bob) ──▶ [Escrow]", rendered)
        self.assertIn("sends 1 ETH", rendered)
        self.assertIn("ETH Bob: +1 ETH", rendered)
        self.assertIn("WHY THIS STEP: Alice funds the escrow for Bob  [LAB CONTROL]", rendered)



if __name__ == "__main__":
    unittest.main()
