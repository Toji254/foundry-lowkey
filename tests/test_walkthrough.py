import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "walkthrough.py"

spec = importlib.util.spec_from_file_location("walkthrough", MODULE)
walkthrough = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = walkthrough
spec.loader.exec_module(walkthrough)


class WalkthroughTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
