import importlib.util
import inspect
import json
import io
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

FINDING_PATTERNS = ROOT / "lowkey" / "walkthrough_finding_patterns.py"
pattern_spec = importlib.util.spec_from_file_location("walkthrough_finding_patterns", FINDING_PATTERNS)
walkthrough_finding_patterns = importlib.util.module_from_spec(pattern_spec)
sys.modules[pattern_spec.name] = walkthrough_finding_patterns
pattern_spec.loader.exec_module(walkthrough_finding_patterns)


class WalkthroughTests(unittest.TestCase):
    def test_review_control_hint_tracks_observed_history(self):
        self.assertEqual(
            walkthrough._review_controls_hint(0),
            "⏎ next  |  no observed steps yet   R = review any observed step  |  q stop",
        )
        self.assertEqual(
            walkthrough._review_controls_hint(2),
            "⏎ next  |  1-2 review observed   R = review any observed step  |  q stop",
        )
        self.assertEqual(
            walkthrough._review_controls_hint(9),
            "⏎ next  |  1-9 review observed   R = review any observed step  |  q stop",
        )
        self.assertEqual(
            walkthrough._review_controls_hint(10),
            "⏎ next  |  1-9 quick review   R = review any observed step (1-10)  |  q stop",
        )
        self.assertEqual(
            walkthrough._review_controls_hint(17),
            "⏎ next  |  1-9 quick review   R = review any observed step (1-17)  |  q stop",
        )
        self.assertEqual(
            walkthrough._walkthrough_board_controls(3),
            "ENTER = next live interaction   1-3 = review observed   R = review any observed step   Q = stop",
        )
        self.assertEqual(
            walkthrough._walkthrough_board_controls(17),
            "ENTER = next live interaction   1-9 = quick review   R = review any observed step (1-17)   Q = stop",
        )

    def test_live_loop_uses_review_state_machine_for_every_pause_point(self):
        source = inspect.getsource(walkthrough.run)
        self.assertEqual(source.count("choice = wait_for_action()"), 2)
        self.assertEqual(source.count("choice = _wait_for_next_interaction(no_prompt, len(steps))"), 1)
        self.assertIn("REVIEW PICKER", source)
        self.assertIn("review_mode=True", source)

    def test_review_help_describes_observed_steps_not_future_steps(self):
        controls = inspect.getsource(walkthrough._walkthrough_board_controls)
        self.assertIn("1-9 = quick review", controls)
        source = inspect.getsource(walkthrough.run)
        self.assertIn("ENTER here resumes live execution", source)

    def test_runtime_walkthrough_contains_no_known_project_specific_adapters(self):
        production_files = [
            ROOT / "lowkey" / "lk.py",
            ROOT / "lowkey" / "audit_context.py",
            ROOT / "lowkey" / "audit_engine.py",
            ROOT / "lowkey" / "bootstrap.py",
            ROOT / "lowkey" / "clone_tools.py",
            ROOT / "lowkey" / "forge_tools.py",
            ROOT / "lowkey" / "generator.py",
            ROOT / "lowkey" / "project_detection.py",
            ROOT / "lowkey" / "project_tools.py",
            ROOT / "lowkey" / "slither_tools.py",
            ROOT / "lowkey" / "system_model.py",
            ROOT / "lowkey" / "walkthrough.py",
        ]
        banned = (
            "ConfidencePool",
            "AaveDIVAWrapper",
            "QuantAMM",
            "Zaros",
            "2026-07-bc-confidence-pools",
            "2024-12-quantamm",
            "2025-01-diva",
        )
        for path in production_files:
            source = path.read_text(encoding="utf-8")
            for token in banned:
                self.assertNotIn(token, source, f"{token} leaked into runtime: {path}")


    def test_local_rpc_detection_is_available_at_runtime(self):
        self.assertTrue(walkthrough._is_local_rpc("http://127.0.0.1:8545"))
        self.assertTrue(walkthrough._is_local_rpc("http://localhost:8545"))
        self.assertFalse(walkthrough._is_local_rpc("https://example.com/rpc"))

    def test_fake_builtin_edges_are_not_external_dependencies(self):
        model = walkthrough.ContractModel(
            name="BountyArena",
            source="src/BountyArena.sol",
            artifact="out/BountyArena.sol/BountyArena.json",
            calls=[
                {"kind": "cross-contract", "from": "createbounty", "to_contract": "BountyArena", "to_function": "encode", "via": "abi"},
                {"kind": "cross-contract", "from": "createbounty", "to_contract": "BountyArena", "to_function": "require", "via": "x"},
                {"kind": "cross-contract", "from": "createbounty", "to_contract": "Registry", "to_function": "isAllowed", "via": "registry"},
            ],
        )
        step = walkthrough.Step(1, "Alice", "BountyArena", "0x" + "1" * 40, "createbounty()", [])
        edges = walkthrough._source_edges_for_step(model, step)
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["to_contract"], "Registry")

    def test_source_dependency_explanations_only_include_real_cross_contract_edges(self):
        model = walkthrough.ContractModel(
            name="BountyArena",
            source="src/BountyArena.sol",
            artifact="out/BountyArena.sol/BountyArena.json",
            calls=[
                {"kind": "internal", "from": "createbounty", "to_contract": "BountyArena", "to_function": "require"},
                {"kind": "internal", "from": "createbounty", "to_contract": "BountyArena", "to_function": "keccak256"},
                {"kind": "internal", "from": "createbounty", "to_contract": "BountyArena", "to_function": "Bounty"},
                {"kind": "cross-contract", "from": "createbounty", "to_contract": "Registry", "to_function": "isAllowed", "via": "registry"},
            ],
        )
        edges = walkthrough._source_edges_for_name(model, "createbounty")
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["to_contract"], "Registry")

    def test_source_semantics_capture_guards_and_state_writes(self):
        model = walkthrough.ContractModel(
            name="Demo",
            source="src/Demo.sol",
            artifact="out/Demo.sol/Demo.json",
            storage={"storage": [{"label": "balance", "slot": "0", "type": "uint256"}]},
        )
        model.mappings = [{"name": "balances", "key_type": "address", "value_type": "uint256"}]
        source = """
        contract Demo {
            mapping(address => uint256) balances;
            function deposit(uint256 amount) external {
                if (amount == 0) revert ZeroAmount();
                balances[msg.sender] += amount;
            }
        }
        """
        model.functions = ["deposit(uint256)"]
        model.calls = []
        model.semantics = walkthrough._function_semantics(model, source)
        self.assertIn("deposit()", model.semantics)
        self.assertTrue(model.semantics["deposit()"]["guards"])
        self.assertIn("balances", model.semantics["deposit()"]["writes"])

    def test_protocol_observation_merge_prefers_live_dependency_roles(self):
        config = {
            "lab_system": {"stake_token": "0x" + "1" * 40},
            "aliases": {"Agreement": "0x" + "2" * 40},
        }
        runtime = [
            walkthrough.RuntimeContract("0x" + "3" * 40, "Pool", "Pool #1", "CLONE"),
        ]
        merged = walkthrough._merge_protocol_observations({}, config=config, runtime=runtime)
        self.assertEqual(merged["staketoken"], "0x" + "1" * 40)
        self.assertEqual(merged["agreement"], "0x" + "2" * 40)
        self.assertEqual(merged["pool"], "0x" + "3" * 40)

    def test_system_workflow_map_includes_source_and_live_edges(self):
        factory = walkthrough.ContractModel(
            name="Factory",
            source="src/Factory.sol",
            artifact="out/Factory.sol/Factory.json",
            functions=["create()"],
            calls=[{
                "kind": "cross-contract",
                "from": "create",
                "to_contract": "Child",
                "to_function": "initialize",
                "via": "child",
            }],
        )
        child = walkthrough.ContractModel(
            name="Child",
            source="src/Child.sol",
            artifact="out/Child.sol/Child.json",
        )
        runtime = [walkthrough.RuntimeContract("0x" + "1" * 40, "Factory", "Factory", "system")]
        rendered = walkthrough._render_system_workflow_graph(
            pathlib.Path("/tmp/project"), [factory, child], runtime, factory, False
        )
        self.assertIn("create()", rendered)
        self.assertIn("Child.initialize()", rendered)

    def test_clickable_function_call_uses_source_target(self):
        model = walkthrough.ContractModel(
            name="Demo",
            source="src/Demo.sol",
            artifact="out/Demo.sol/Demo.json",
            functions=["setValue(uint256)"],
            function_locations={"setValue": 17},
        )
        actors = [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)]
        step = walkthrough.Step(
            1, "Alice", "Demo", "0x" + "2" * 40, "setValue(uint256)", [7], status="planned"
        )
        rendered = walkthrough._render_interaction_graph(
            pathlib.Path("/tmp/project"), step, actors, model, [model], False
        )
        self.assertIn("setValue(7)", rendered)
        self.assertTrue(
            "vscode://file//tmp/project/src/Demo.sol:17" in rendered
            or "cursor://file//tmp/project/src/Demo.sol:17" in rendered
            or "file:///tmp/project/src/Demo.sol" in rendered
        )

    def test_transaction_link_uses_configured_explorer(self):
        tx = "0x" + "1" * 64
        with patch.dict(
            walkthrough.os.environ,
            {"LOWKEY_TX_EXPLORER_URL": "https://example.explorer/tx/{tx}"},
            clear=True,
        ):
            rendered = walkthrough._transaction_link(pathlib.Path("/tmp/project"), tx, rpc="https://rpc.example")
        self.assertIn("https://example.explorer/tx/" + tx, rendered)
        self.assertNotIn("file://", rendered)

    def test_transaction_link_auto_detects_known_public_chain(self):
        tx = "0x" + "2" * 64
        with patch.dict(walkthrough.os.environ, {}, clear=True):
            with patch.object(walkthrough, "_rpc_call", return_value="0x14a34"):
                rendered = walkthrough._transaction_link(
                    pathlib.Path("/tmp/project"), tx, rpc="https://sepolia.base.org"
                )
        self.assertIn("https://sepolia.basescan.org/tx/" + tx, rendered)
        self.assertNotIn("file://", rendered)

    def test_transaction_link_keeps_local_anvil_transactions_local(self):
        tx = "0x" + "3" * 64
        with patch.dict(walkthrough.os.environ, {}, clear=True):
            rendered = walkthrough._transaction_link(
                pathlib.Path("/tmp/project"), tx, rpc="http://127.0.0.1:8545"
            )
        self.assertIn("file:///tmp/project/.audit/walkthrough/transactions/" + tx.lower() + ".html", rendered)

    def test_transaction_evidence_uses_confirmed_on_chain_observation(self):
        tx_hash = "0x" + "4" * 64
        root = pathlib.Path(tempfile.mkdtemp())
        step = walkthrough.Step(
            1, "Alice", "Demo", "0x" + "5" * 40, "setValue(uint256)", [7],
            status="checking", tx_hash=tx_hash,
        )

        def rpc(_rpc_url, method, params=None):
            if method == "eth_getTransactionByHash":
                return {
                    "hash": tx_hash,
                    "from": "0x" + "6" * 40,
                    "to": "0x" + "5" * 40,
                    "value": "0x0",
                    "nonce": "0x1",
                    "blockNumber": "0x2a",
                    "gas": "0x5208",
                    "input": "0x552410770000000000000000000000000000000000000000000000000000000000000007",
                }
            return None

        receipt = {"status": "0x1", "blockNumber": "0x2a", "gasUsed": "0x5208"}
        with patch.object(walkthrough, "_rpc_call", side_effect=rpc):
            path = walkthrough._write_transaction_evidence(
                root, "http://127.0.0.1:8545", step, receipt
            )
        self.assertIsNotNone(path)
        html = path.read_text(encoding="utf-8")
        self.assertIn('"lowkey_status_at_render": &quot;checking&quot;', html)
        self.assertIn('"on_chain_status": &quot;CONFIRMED / SUCCESS&quot;', html)
        self.assertIn('"gas_used": &quot;21000&quot;', html)
        self.assertIn("0x552410770000000000000000000000000000000000000000000000000000000000000007", html)

    def test_live_target_rejects_eoa_even_for_non_initializer_contract(self):
        model = walkthrough.ContractModel(
            name="Fallback",
            source="src/Fallback.sol",
            artifact="out/Fallback.sol/Fallback.json",
            abi=[{
                "type": "function",
                "name": "withdraw",
                "inputs": [],
                "outputs": [],
                "stateMutability": "nonpayable",
            }],
        )
        with patch.object(walkthrough, "_runtime_code", return_value="0x"):
            ok, reason = walkthrough._target_is_live_instance(
                pathlib.Path("/tmp/project"),
                "http://127.0.0.1:8545",
                "0x" + "1" * 40,
                model,
            )
        self.assertFalse(ok)
        self.assertIn("no contract bytecode", reason)

    def test_friendly_eth_shows_compact_eth_and_exact_wei(self):
        self.assertEqual(walkthrough._friendly_eth(1), "1e-18 ETH [1 wei]")
        self.assertEqual(
            walkthrough._friendly_eth(10**18),
            "1 ETH [1,000,000,000,000,000,000 wei]",
        )
        self.assertEqual(
            walkthrough._friendly_eth(1000 * 10**18 + 3),
            "1,000 ETH + 3 wei [1,000,000,000,000,000,000,003 wei]",
        )

    def test_storage_renderer_is_meaning_first_for_mapping_rows_and_slots(self):
        storage = [
            {
                "label": "contributions",
                "slot": "0",
                "type": "mapping(address => uint256)",
                "encoding": "mapping",
                "mapping": {
                    "key_type": "address",
                    "value_type": "uint256",
                    "native_value": True,
                    "rows": [{
                        "key": "0x" + "1" * 40,
                        "value": 1000 * 10**18 + 3,
                        "slot": "0x" + "2" * 64,
                        "raw": "0x" + "4" * 64,
                    }],
                },
            },
            {
                "label": "owner",
                "slot": "1",
                "type": "address",
                "encoding": "inplace",
                "value": "0x" + "3" * 40,
                "raw": "0x" + "0" * 24 + "3" * 40,
            },
        ]
        actors = [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)]
        rendered = walkthrough._render_storage(storage, False, actors)
        self.assertIn("purpose       → keeps track of how much ETH each address has contributed", rendered)
        self.assertIn("mapping slot  → 0   [the mapping's anchor; this slot identifies the mapping itself]", rendered)
        self.assertIn("important     → slot 0 is not Alice's value; it helps the EVM find Alice's entry", rendered)
        self.assertIn("key type      → address   [what identifies an entry]", rendered)
        self.assertIn("value type    → uint256   [what is stored for that key]", rendered)
        self.assertIn("Alice → 1,000 ETH + 3 wei", rendered)
        self.assertNotIn("1,000,000,000,000,000,000,003 wei", rendered)
        self.assertIn("SLOT 1 • owner", rendered)
        self.assertIn("purpose       → remembers the current owner", rendered)
        self.assertIn("value         → 0x33333333…33333333", rendered)
        self.assertIn("storage box", rendered)
        self.assertIn("numbered storage box", rendered)
        self.assertNotIn("raw word", rendered)

    def test_storage_renderer_uses_nonzero_mapping_slot_in_human_explanation(self):
        storage = [{
            "label": "balances",
            "slot": "7",
            "type": "mapping(address => uint256)",
            "encoding": "mapping",
            "mapping": {
                "key_type": "address",
                "value_type": "uint256",
                "rows": [{
                    "key": "0x" + "1" * 40,
                    "value": 1,
                }],
            },
        }]
        actors = [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)]
        rendered = walkthrough._render_storage(storage, False, actors)
        self.assertIn("mapping slot  → 7", rendered)
        self.assertIn("important     → slot 7 is not Alice's value; it helps the EVM find Alice's entry", rendered)
        self.assertIn("entry location→ each key gets its own storage location using the key + mapping slot 7", rendered)
        self.assertIn("hash(Alice's address + slot 7) → Alice's storage location", rendered)
        self.assertNotIn("Alice's address + slot 0", rendered)

    def test_storage_renderer_keeps_mapping_slot_evidence_in_technical_mode(self):
        storage = [{
            "label": "contributions",
            "slot": "0",
            "type": "mapping(address => uint256)",
            "encoding": "mapping",
            "mapping": {
                "key_type": "address",
                "value_type": "uint256",
                "native_value": True,
                "rows": [{
                    "key": "0x" + "1" * 40,
                    "value": 1,
                    "slot": "0x" + "2" * 64,
                }],
            },
        }]
        rendered = walkthrough._render_storage(storage, False, [], technical=True)
        self.assertIn("technical storage:", rendered)
        self.assertIn("mapping base slot = 0", rendered)
        self.assertIn("row location        = keccak256(pad(key) || pad(0))", rendered)
        self.assertIn("row slot 0x" + "2" * 20, rendered)

    def test_security_radar_uses_real_newlines(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            patterns = root / ".audit" / "security_patterns.json"
            patterns.parent.mkdir(parents=True)
            patterns.write_text(json.dumps({
                "patterns": [{
                    "pattern_id": "REPLAY-001",
                    "verification_status": "CANDIDATE",
                    "contract": "Fallback",
                    "function": "withdraw",
                    "title": "Replayable payout / claim path",
                }]
            }), encoding="utf-8")
            with patch.object(
                walkthrough,
                "audit_context",
                None,
                create=True,
            ):
                # The renderer imports audit_context itself; verify the rendering
                # contract directly by patching the imported module.
                fake = type("Context", (), {
                    "security_patterns": lambda self, _root: [{
                        "pattern_id": "REPLAY-001",
                        "verification_status": "CANDIDATE",
                        "contract": "Fallback",
                        "function": "withdraw",
                        "title": "Replayable payout / claim path",
                    }]
                })()
                with patch.dict(sys.modules, {"audit_context": fake}):
                    rendered = walkthrough._render_security_radar(root, walkthrough.ContractModel(
                        name="Fallback",
                        source="src/Fallback.sol",
                        artifact="out/Fallback.sol/Fallback.json",
                    ), False)
        self.assertIn("SECURITY RADAR\n  Shared signals", rendered)
        self.assertNotIn("\\n", rendered)

    def test_render_board_accepts_technical_storage_flag(self):
        model = walkthrough.ContractModel(
            name="Demo",
            source="src/Demo.sol",
            artifact="out/Demo.sol/Demo.json",
        )
        rendered = walkthrough._render_board(
            pathlib.Path("/tmp/project"),
            model,
            [model],
            [walkthrough.RuntimeContract("0x" + "1" * 40, "Demo", "Demo", "target")],
            [walkthrough.Actor("Alice", "0x" + "2" * 40, 0)],
            [],
            None,
            [],
            False,
            technical_storage=True,
        )
        self.assertIn("LOWKEY // LIVE PROTOCOL WALKTHROUGH", rendered)

    def test_cli_arg_lowercases_booleans(self):
        self.assertEqual(walkthrough._cli_arg(True), "true")
        self.assertEqual(walkthrough._cli_arg(False), "false")

    def test_protocol_root_and_child_are_inferred_from_source_graph(self):
        factory = walkthrough.ContractModel(
            name="DemoFactory",
            source="src/DemoFactory.sol",
            artifact="out/DemoFactory.sol/DemoFactory.json",
            abi=[{
                "type": "function",
                "name": "initialize",
                "inputs": [{"name": "implementation", "type": "address"}],
                "outputs": [],
            }, {
                "type": "function",
                "name": "createPool",
                "inputs": [],
                "outputs": [],
            }],
            functions=["initialize(address)", "createPool()"],
            calls=[{
                "kind": "cross-contract",
                "from": "createPool",
                "to_contract": "IPool",
                "to_function": "initialize",
                "via": "pool",
            }],
        )
        pool = walkthrough.ContractModel(
            name="Pool",
            source="src/Pool.sol",
            artifact="out/Pool.sol/Pool.json",
            abi=[{
                "type": "function",
                "name": "initialize",
                "inputs": [],
                "outputs": [],
            }],
            functions=["initialize()"],
        )
        self.assertEqual(walkthrough._infer_protocol_root([factory, pool]).name, "DemoFactory")
        self.assertEqual(walkthrough._infer_child_model(factory, [factory, pool]).name, "Pool")

    def test_adversarial_random_values_include_roles_and_extremes(self):
        actors = [
            walkthrough.Actor("Alice", "0x" + "1" * 40, 0),
            walkthrough.Actor("Bob", "0x" + "2" * 40, 1),
            walkthrough.Actor("Attacker", "0x" + "3" * 40, 2),
        ]
        rng = __import__("random").Random(7)
        seen = set()
        for _ in range(80):
            value = walkthrough._random_sol_value(
                {"name": "recipient", "type": "address"},
                actors,
                "0x" + "4" * 40,
                rng,
                {},
            )
            seen.add(value)
        self.assertIn(actors[0].address, seen)
        self.assertIn(actors[1].address, seen)

        numeric = {
            walkthrough._random_sol_value(
                {"name": "amount", "type": "uint256"},
                actors,
                "0x" + "4" * 40,
                rng,
                {},
            )
            for _ in range(100)
        }
        self.assertIn(0, numeric)
        self.assertIn(2**256 - 1, numeric)

    def test_compiler_ast_edges_capture_interface_calls_and_contract_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            source = "pragma solidity ^0.8.20; contract Factory { function create() external { child.initialize(); IRegistry(address(registry)).check(); } address registry; }"
            (root / "src" / "Factory.sol").write_text(source, encoding="utf-8")
            ast = {
                "nodeType":"SourceUnit", "src":"0:1:0",
                "nodes":[
                    {"nodeType":"ContractDefinition","id":1,"name":"Factory",
                     "nodes":[
                        {"nodeType":"FunctionDefinition","id":2,"name":"create","src":"34:80:0",
                         "body":{"nodeType":"Block","src":"60:50:0","statements":[
                            {"nodeType":"ExpressionStatement","expression":{"nodeType":"FunctionCall","src":"70:10:0",
                             "expression":{"nodeType":"MemberAccess","memberName":"initialize",
                              "expression":{"nodeType":"Identifier","name":"child","referencedDeclaration":3,"typeDescriptions":{"typeString":"contract Child storage ref"}}},
                             "arguments":[]}},
                            {"nodeType":"ExpressionStatement","expression":{"nodeType":"FunctionCall","src":"90:25:0",
                             "expression":{"nodeType":"MemberAccess","memberName":"check",
                              "expression":{"nodeType":"FunctionCall","src":"90:18:0","expression":{"nodeType":"Identifier","name":"IRegistry"},"arguments":[{"nodeType":"Identifier","name":"registry"}]},
                              "arguments":[]}},
                             }
                         ]}}
                     ]},
                    {"nodeType":"VariableDeclaration","id":3,"name":"child","typeDescriptions":{"typeString":"contract Child storage ref"}},
                ]
            }
            payload={"output":{"sources":{"src/Factory.sol":{"ast":ast}, "src/Child.sol":{}, "src/IRegistry.sol":{}}, "contracts":{}}}
            (root / "out" / "build-info").mkdir(parents=True)
            (root / "out" / "build-info" / "x.json").write_text(json.dumps(payload), encoding="utf-8")
            model=walkthrough.ContractModel(name="Factory",source="src/Factory.sol",artifact="out/Factory.sol/Factory.json",functions=["create()"])
            edges=walkthrough._build_info_ast_calls(root,model)
        self.assertTrue(any(e.get("to_function")=="initialize" and e.get("to_contract")=="Child" for e in edges))
        self.assertTrue(any(e.get("to_function")=="check" and e.get("interface")=="IRegistry" for e in edges))

    def test_contract_requirement_follows_internal_helper_and_forwarded_argument(self):
        factory = walkthrough.ContractModel(
            name="Factory",
            source="src/Factory.sol",
            artifact="out/Factory.sol/Factory.json",
            abi=[{
                "type": "function",
                "name": "createPool",
                "inputs": [{"name": "agreement", "type": "address"}],
            }],
            functions=["createPool(address)", "_create(address)"],
            calls=[
                {
                    "kind": "internal",
                    "from": "createPool",
                    "to_contract": "Factory",
                    "to_function": "_create(address)",
                    "argument_names": ["agreement"],
                },
            ],
        )
        helper = walkthrough.ContractModel(
            name="Factory",
            source="src/Factory.sol",
            artifact="out/Factory.sol/Factory.json",
            abi=[
                {
                    "type": "function",
                    "name": "_create",
                    "inputs": [{"name": "agreement_", "type": "address"}],
                }
            ],
            functions=["_create(address)"],
            calls=[],
        )
        helper.calls = [
            {
                "kind": "cross-contract",
                "from": "_create",
                "to_contract": "IAgreement",
                "to_function": "owner",
                "via": "agreement_",
                "argument_names": [],
            }
        ]

        # The catalog can contain one model object per source; the recursion uses
        # the same model for internal calls, so test that path directly.
        factory.calls.append({
            "kind": "cross-contract",
            "from": "_create",
            "to_contract": "IAgreement",
            "to_function": "owner",
            "via": "agreement",
            "argument_names": [],
        })
        self.assertEqual(
            walkthrough._contract_requirement_for_parameter(
                factory,
                "createPool",
                "agreement",
                [factory],
            ),
            "IAgreement",
        )

    def test_value_solver_respects_strict_msg_value_upper_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            src = root / "src"
            src.mkdir(parents=True)
            source = src / "Fallback.sol"
            source.write_text(
                "pragma solidity ^0.8.20;\n"
                "contract Fallback {\n"
                "    function contribute() external payable {\n"
                "        require(msg.value < 0.001 ether);\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            model = walkthrough.ContractModel(
                name="Fallback",
                source="src/Fallback.sol",
                artifact="out/Fallback.sol/Fallback.json",
                abi=[{
                    "type": "function",
                    "name": "contribute",
                    "inputs": [],
                    "outputs": [],
                    "stateMutability": "payable",
                }],
            )
            self.assertEqual(
                walkthrough._value_for(model.abi[0], model=model, root=root),
                1,
            )

    def test_value_solver_uses_minimal_probe_for_raw_payable_entry_without_source(self):
        model = walkthrough.ContractModel(
            name="Demo",
            source="src/Demo.sol",
            artifact="out/Demo.sol/Demo.json",
        )
        for entry_type in ("receive", "fallback"):
            entry = {"type": entry_type, "stateMutability": "payable"}
            self.assertEqual(
                walkthrough._value_for(entry, model=model, root=pathlib.Path("/tmp/nonexistent")),
                1,
            )

    def test_value_solver_reads_receive_msg_value_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            src = root / "src"
            src.mkdir(parents=True)
            source = src / "Demo.sol"
            source.write_text(
                "pragma solidity ^0.8.20;\n"
                "contract Demo {\n"
                "    mapping(address => uint256) public contributions;\n"
                "    receive() external payable {\n"
                "        require(msg.value > 0 && contributions[msg.sender] > 0);\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            model = walkthrough.ContractModel(
                name="Demo",
                source="src/Demo.sol",
                artifact="out/Demo.sol/Demo.json",
            )
            entry = {"type": "receive", "name": "receive", "inputs": [], "stateMutability": "payable"}
            self.assertEqual(walkthrough._value_for(entry, model=model, root=root), 1)

    def test_plan_workflow_includes_payable_fallback_entry(self):
        model = walkthrough.ContractModel(
            name="Fallback",
            source="src/Fallback.sol",
            artifact="out/Fallback.sol/Fallback.json",
            abi=[
                {
                    "type": "function",
                    "name": "contribute",
                    "inputs": [],
                    "outputs": [],
                    "stateMutability": "payable",
                },
                {"type": "fallback", "stateMutability": "payable"},
                {
                    "type": "function",
                    "name": "withdraw",
                    "inputs": [],
                    "outputs": [],
                    "stateMutability": "nonpayable",
                },
            ],
        )
        actors = [
            walkthrough.Actor("Alice", "0x" + "1" * 40, 0),
            walkthrough.Actor("Bob", "0x" + "2" * 40, 1),
        ]
        steps = walkthrough.plan_workflow(
            model, actors, "0x" + "3" * 40, 100, 5
        )
        self.assertTrue(any(step.function == "fallback()" for step in steps))

    def test_empty_revert_explanation_points_to_dependency_layer(self):
        step = walkthrough.Step(
            1,
            "Alice",
            "Factory",
            "0x" + "1" * 40,
            "create(address)",
            ["0x" + "2" * 40],
            status="blocked",
            error='server returned an error response: error code 3: execution reverted, data: "0x"',
        )
        text = walkthrough._explain_failure(step, step.error, "Alice")
        self.assertIn("Lowkey could not decode the exact failing instruction", text)
        self.assertIn("empty revert payload", text)

    def test_render_board_marks_a_reopened_observed_step_as_review(self):
        actors = [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)]
        model = walkthrough.ContractModel(
            name="Demo",
            source="src/Demo.sol",
            artifact="out/Demo.sol/Demo.json",
            functions=["deposit()", "withdraw()"],
        )
        first = walkthrough.Step(
            1, "Alice", "Demo", "0x" + "2" * 40,
            "deposit()", [], status="success",
        )
        second = walkthrough.Step(
            2, "Alice", "Demo", "0x" + "2" * 40,
            "withdraw()", [], status="success",
        )
        rendered = walkthrough._render_board(
            pathlib.Path("/tmp/project"),
            model,
            [model],
            [walkthrough.RuntimeContract("0x" + "2" * 40, "Demo", "Demo", "target")],
            actors,
            [first, second],
            first,
            first.storage_after,
            False,
        )
        self.assertIn("REVIEW MODE: recorded evidence only; no transaction is re-run.", rendered)
        self.assertIn("REVIEWING  •  FUNCTION 01  •  OBSERVED", rendered)

    def test_live_story_keeps_previous_steps_compact_and_current_step_expanded(self):
        actors = [
            walkthrough.Actor("Alice", "0x" + "1" * 40, 0),
            walkthrough.Actor("Bob", "0x" + "2" * 40, 1),
        ]
        model = walkthrough.ContractModel(
            name="Pool",
            source="src/Pool.sol",
            artifact="out/Pool.sol/Pool.json",
            functions=["deposit()", "withdraw()"],
            function_locations={"deposit": 10, "withdraw": 20},
        )
        first = walkthrough.Step(
            1, "Alice", "Pool", "0x" + "3" * 40,
            "deposit()", [], value_wei=10**18, status="success",
        )
        second = walkthrough.Step(
            2, "Bob", "Pool", "0x" + "3" * 40,
            "withdraw()", [], status="checking",
        )
        rendered = walkthrough._render_protocol_story_full(
            pathlib.Path("/tmp/project"),
            [first, second],
            second,
            actors,
            [model],
            False,
        )
        self.assertIn("01", rendered)
        self.assertIn("02", rendered)
        self.assertIn("▼", rendered)
        self.assertIn("Pool.withdraw()", rendered)

    def test_test_flow_hints_capture_ordered_behavior_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            (root/"test").mkdir()
            (root/"test"/"Flow.t.sol").write_text(
                """contract Flow { function testLifecycle() external { factory.setAllowed(token, true); factory.createPool(a); pool.stake(1); pool.withdraw(1); } }""",
                encoding="utf-8"
            )
            model=walkthrough.ContractModel(
                name="Factory",source="src/Factory.sol",artifact="out/Factory.sol/Factory.json",
                abi=[
                    {"type":"function","name":"setAllowed","inputs":[]},
                    {"type":"function","name":"createPool","inputs":[]},
                    {"type":"function","name":"stake","inputs":[]},
                    {"type":"function","name":"withdraw","inputs":[]},
                ],
            )
            hints=walkthrough._test_flow_hints(root,model)
        self.assertLess(hints["setAllowed"][0], hints["createPool"][0])
        self.assertLess(hints["createPool"][0], hints["stake"][0])
        self.assertLess(hints["stake"][0], hints["withdraw"][0])

    def test_system_live_core_is_protocol_agnostic(self):
        config = {
            "target": "0x" + "1" * 40,
            "lab_system": {
                "root": "0x" + "1" * 40,
                "root_model": "DemoRouter",
                "vault": "0x" + "2" * 40,
                "vault_model": "DemoVault",
            },
        }
        def fake_code(rpc, address):
            return "0x6000" if address in {"0x" + "1" * 40, "0x" + "2" * 40} else "0x"
        with patch.object(walkthrough, "_runtime_code", side_effect=fake_code):
            self.assertTrue(walkthrough._system_has_live_core(config, "http://127.0.0.1:8545"))
    def test_failure_flow_summary_shows_first_blocker_and_unreached_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "Factory.sol").write_text(
                """contract Factory { mapping(address => bool) public allowed; function create(address token) external { if (!allowed[token]) revert(); IRegistry(registry).check(); IAgreement(agreement).owner(); } address registry; address agreement; }""",
                encoding="utf-8",
            )
            model = walkthrough.ContractModel(
                name="Factory", source="src/Factory.sol", artifact="out/Factory.sol/Factory.json",
                abi=[{"type":"function","name":"create","inputs":[{"name":"token","type":"address"}]}],
                functions=["create(address)"],
                calls=[
                    {"kind":"cross-contract","from":"create","to_contract":"IRegistry","to_function":"check","via":"registry"},
                    {"kind":"cross-contract","from":"create","to_contract":"IAgreement","to_function":"owner","via":"agreement"},
                ],
            )
            step = walkthrough.Step(1,"Alice","Factory","0x"+"1"*40,"create(address)",["0x"+"2"*40])
            lines = walkthrough._failure_flow_summary(root, model, step, "Factory.create → allowed[token] is false")
        joined=" ".join(lines)
        self.assertIn("FIRST BLOCKER", joined)
        self.assertIn("allowed[token] is false", joined)
        self.assertIn("NOT REACHED", joined)
        self.assertIn("IRegistry.check()", joined)
    def test_infer_protocol_root_has_plain_application_fallback(self):
        plain=walkthrough.ContractModel(
            name="Vault",source="src/Vault.sol",artifact="out/Vault.sol/Vault.json",kind="contract",
            abi=[{"type":"function","name":"deposit","inputs":[],"stateMutability":"nonpayable"}],
            functions=["deposit()"],
        )
        self.assertEqual(walkthrough._infer_protocol_root([plain]).name,"Vault")
    def test_source_guard_probe_identifies_exact_mapping_key_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            source = """
            pragma solidity ^0.8.20;
            contract DemoFactory {
                mapping(address => bool) public allowedToken;
                address public ownerAddress;
                function owner() external view returns (address) { return ownerAddress; }
                function createPool(address agreement, address token, uint256 expiry) external onlyOwner {
                    if (agreement == address(0)) revert();
                    if (!allowedToken[token]) revert();
                    if (expiry < block.timestamp + MIN_LEAD) revert();
                }
                uint256 constant MIN_LEAD = 30 days;
            }
            """
            (root / "src" / "DemoFactory.sol").write_text(source, encoding="utf-8")
            model = walkthrough.ContractModel(
                name="DemoFactory", source="src/DemoFactory.sol", artifact="out/DemoFactory.sol/DemoFactory.json",
                abi=[
                    {"type":"function","name":"createPool","inputs":[
                        {"name":"agreement","type":"address"},{"name":"token","type":"address"},{"name":"expiry","type":"uint256"}],
                        "outputs":[],"stateMutability":"nonpayable"},
                    {"type":"function","name":"allowedToken","inputs":[{"name":"","type":"address"}],
                        "outputs":[{"type":"bool"}],"stateMutability":"view"},
                    {"type":"function","name":"owner","inputs":[],"outputs":[{"type":"address"}],"stateMutability":"view"},
                ],
                functions=["createPool(address,address,uint256)"],
                mappings=[{"name":"allowedToken","key_type":"address","value_type":"bool"}],
            )
            step = walkthrough.Step(1,"Bob","DemoFactory","0x"+"3"*40,"createPool(address,address,uint256)",
                                   ["0x"+"4"*40,"0x"+"5"*40,100],status="blocked")
            alice = "0x" + "1"*40
            with patch.object(
                walkthrough,
                "_read_contract_getter",
                side_effect=[(True, alice), (True, "false")],
            ), patch.object(
                walkthrough,
                "_block_timestamp",
                return_value=100,
            ):
                origin, lines = walkthrough._probe_source_guards(root,"http://127.0.0.1:8545",step,model,[model],alice)
        self.assertIn("allowedToken", " ".join(lines))
        self.assertTrue(any(line.startswith("✕") and "allowedToken" in line for line in lines))
        self.assertIn("allowedToken[token] is false", origin)

    def test_output_signature_includes_return_types_for_live_getters(self):
        item = {"name":"owner","inputs":[],"outputs":[{"type":"address"}],"type":"function"}
        self.assertEqual(walkthrough._output_signature(item), "owner()(address)")

    def test_lab_runtime_is_protocol_name_agnostic(self):
        config = {
            "lab_system": {
                "root": "0x"+"1"*40, "root_model":"DemoRouter",
                "router": "0x"+"1"*40, "router_model":"DemoRouter",
                "vault": "0x"+"2"*40, "vault_model":"DemoVault",
            }
        }
        router = walkthrough.ContractModel(name="DemoRouter",source="src/DemoRouter.sol",artifact="out/DemoRouter.sol/DemoRouter.json")
        vault = walkthrough.ContractModel(name="DemoVault",source="src/DemoVault.sol",artifact="out/DemoVault.sol/DemoVault.json")
        runtime = walkthrough._lab_runtime(config,"0x"+"1"*40,router,[router,vault])
        self.assertTrue(any(node.label == "DemoRouter" for node in runtime))
        self.assertTrue(any(node.label == "DemoVault" and node.relation == "DEPENDENCY" for node in runtime))

    def test_random_test_mode_keeps_extreme_values_generic(self):
        actors=[walkthrough.Actor("Alice","0x"+"1"*40,0), walkthrough.Actor("Bob","0x"+"2"*40,1), walkthrough.Actor("Attacker","0x"+"3"*40,2)]
        rng=__import__("random").Random(1234)
        values={walkthrough._random_sol_value({"name":"value","type":"uint256"},actors,"0x"+"4"*40,rng,{}) for _ in range(100)}
        self.assertIn(0,values)
        self.assertIn(2**256-1,values)
    def test_plan_workflow_is_generic_and_lifecycle_aware(self):
        model = walkthrough.ContractModel(
            name="DemoPool",
            source="src/DemoPool.sol",
            artifact="out/DemoPool.sol/DemoPool.json",
            functions=["deposit(uint256)", "withdraw()", "pause()"],
            abi=[
                {"type":"function","name":"deposit","inputs":[{"name":"amount","type":"uint256"}],"stateMutability":"payable"},
                {"type":"function","name":"withdraw","inputs":[],"stateMutability":"nonpayable"},
                {"type":"function","name":"pause","inputs":[],"stateMutability":"nonpayable"},
            ],
        )
        actors = [walkthrough.Actor("Alice","0x"+"1"*40,0), walkthrough.Actor("Bob","0x"+"2"*40,1)]
        recipe = walkthrough.plan_workflow(model, actors, "0x"+"3"*40, 100, 8)
        names = [step.function for step in recipe]
        self.assertTrue(names)
        self.assertIn("deposit(uint256)", names)
        self.assertIn("withdraw()", names)
        self.assertNotIn("pause()", names)

    def test_project_specific_confidence_pool_adapters_are_removed_from_runtime(self):
        self.assertFalse(hasattr(walkthrough, "_confidence_pool_recipe"))
        self.assertFalse(hasattr(walkthrough, "_confidence_pool_factory_recipe"))

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

    def test_contract_typed_address_uses_observed_dependency(self):
        model = walkthrough.ContractModel(
            name="Factory",
            source="src/Factory.sol",
            artifact="out/Factory.sol/Factory.json",
            functions=["createPool(address,address)"],
            calls=[
                {
                    "kind": "cross-contract",
                    "from": "createPool",
                    "to_contract": "IAgreement",
                    "to_function": "owner",
                    "via": "agreement",
                },
            ],
        )
        actors = [
            walkthrough.Actor("Alice", "0x" + "1" * 40, 0),
            walkthrough.Actor("Bob", "0x" + "2" * 40, 1),
        ]
        agreement = "0x" + "9" * 40
        value = walkthrough._arg_for(
            {"name": "agreement", "type": "address"},
            actors,
            actors[0].address,
            100,
            {"agreement": agreement},
            model,
            "createPool",
        )
        self.assertEqual(value, agreement)

    def test_contract_typed_address_never_falls_back_to_actor(self):
        model = walkthrough.ContractModel(
            name="Factory",
            source="src/Factory.sol",
            artifact="out/Factory.sol/Factory.json",
            abi=[{
                "type": "function",
                "name": "createPool",
                "inputs": [{"name": "agreement", "type": "address"}],
                "outputs": [],
                "stateMutability": "nonpayable",
            }],
            functions=["createPool(address)"],
            calls=[
                {
                    "kind": "cross-contract",
                    "from": "createPool",
                    "to_contract": "IAgreement",
                    "to_function": "owner",
                    "via": "agreement",
                },
            ],
        )
        actors = [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)]
        value = walkthrough._arg_for(
            {"name": "agreement", "type": "address"},
            actors,
            actors[0].address,
            100,
            {},
            model,
            "createPool",
        )
        self.assertIsNone(value)

    def test_validate_step_arguments_blocks_missing_contract_dependency(self):
        model = walkthrough.ContractModel(
            name="Factory",
            source="src/Factory.sol",
            artifact="out/Factory.sol/Factory.json",
            abi=[{
                "type": "function",
                "name": "createPool",
                "inputs": [{"name": "agreement", "type": "address"}],
                "outputs": [],
                "stateMutability": "nonpayable",
            }],
            functions=["createPool(address)"],
            calls=[
                {
                    "kind": "cross-contract",
                    "from": "createPool",
                    "to_contract": "IAgreement",
                    "to_function": "owner",
                    "via": "agreement",
                },
            ],
        )
        step = walkthrough.Step(
            1,
            "Alice",
            "Factory",
            "0x" + "2" * 40,
            "createPool(address)",
            [None],
        )
        ok, reason = walkthrough._validate_step_arguments(step, model)
        self.assertFalse(ok)
        self.assertIn("agreement", reason)
        self.assertIn("IAgreement", reason)

    def test_generic_plan_uses_observed_dependency_argument(self):
        agreement = "0x" + "b" * 40
        actors = [
            walkthrough.Actor("Alice", "0x" + "1" * 40, 0),
            walkthrough.Actor("Bob", "0x" + "2" * 40, 1),
        ]
        model = walkthrough.ContractModel(
            name="Factory",
            source="src/Factory.sol",
            artifact="out/Factory.sol/Factory.json",
            functions=["createPool(address)"],
            abi=[{
                "type":"function","name":"createPool",
                "inputs":[{"name":"agreement","type":"address"}],
                "stateMutability":"nonpayable",
            }],
        )
        recipe = walkthrough.plan_workflow(
            model, actors, "0x"+"3"*40, 100, 1, observed={"agreement": agreement}
        )
        self.assertEqual(recipe[0].args[0], agreement)
        self.assertTrue(recipe[0].inferred)

    def test_auxiliary_project_models_are_available_for_runtime_decoding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "test" / "mocks").mkdir(parents=True)
            (root / "out" / "Demo.sol").mkdir(parents=True)
            (root / "out" / "MockToken.sol").mkdir(parents=True)
            (root / "foundry.toml").write_text(
                '[profile.default]\nsrc = "src"\n',
                encoding="utf-8",
            )
            (root / "src" / "Demo.sol").write_text(
                "pragma solidity ^0.8.20; contract Demo { function ping() external {} }",
                encoding="utf-8",
            )
            (root / "test" / "mocks" / "MockToken.sol").write_text(
                "pragma solidity ^0.8.20; contract MockToken { function transfer(address,uint256) external {} }",
                encoding="utf-8",
            )
            (root / "out" / "Demo.sol" / "Demo.json").write_text(
                json.dumps({
                    "contractName": "Demo",
                    "sourceName": "src/Demo.sol",
                    "abi": [{"type":"function","name":"ping","inputs":[],"outputs":[]}],
                }),
                encoding="utf-8",
            )
            (root / "out" / "MockToken.sol" / "MockToken.json").write_text(
                json.dumps({
                    "contractName": "MockToken",
                    "sourceName": "test/mocks/MockToken.sol",
                    "abi": [{
                        "type":"function","name":"transfer",
                        "inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],
                        "outputs":[{"type":"bool"}],
                    }],
                }),
                encoding="utf-8",
            )
            app_models = walkthrough._artifact_models(root)
            all_models = walkthrough._artifact_models(root, include_aux=True)

        self.assertEqual([item.name for item in app_models], ["Demo"])
        self.assertIn("MockToken", [item.name for item in all_models])

    def test_contract_typed_address_uses_observed_dependency(self):
        model = walkthrough.ContractModel(
            name="Factory",
            source="src/Factory.sol",
            artifact="out/Factory.sol/Factory.json",
            functions=["createPool(address,address)"],
            calls=[
                {
                    "kind": "cross-contract",
                    "from": "createPool",
                    "to_contract": "IAgreement",
                    "to_function": "owner",
                    "via": "agreement",
                },
            ],
        )
        actors = [
            walkthrough.Actor("Alice", "0x" + "1" * 40, 0),
            walkthrough.Actor("Bob", "0x" + "2" * 40, 1),
        ]
        agreement = "0x" + "9" * 40
        value = walkthrough._arg_for(
            {"name": "agreement", "type": "address"},
            actors,
            actors[0].address,
            100,
            {"agreement": agreement},
            model,
            "createPool",
        )
        self.assertEqual(value, agreement)

    def test_contract_typed_address_never_falls_back_to_actor(self):
        model = walkthrough.ContractModel(
            name="Factory",
            source="src/Factory.sol",
            artifact="out/Factory.sol/Factory.json",
            functions=["createPool(address)"],
            calls=[
                {
                    "kind": "cross-contract",
                    "from": "createPool",
                    "to_contract": "IAgreement",
                    "to_function": "owner",
                    "via": "agreement",
                },
            ],
        )
        actors = [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)]
        value = walkthrough._arg_for(
            {"name": "agreement", "type": "address"},
            actors,
            actors[0].address,
            100,
            {},
            model,
            "createPool",
        )
        self.assertIsNone(value)

    def test_validate_step_arguments_blocks_missing_contract_dependency(self):
        model = walkthrough.ContractModel(
            name="Factory",
            source="src/Factory.sol",
            artifact="out/Factory.sol/Factory.json",
            functions=["createPool(address)"],
            calls=[
                {
                    "kind": "cross-contract",
                    "from": "createPool",
                    "to_contract": "IAgreement",
                    "to_function": "owner",
                    "via": "agreement",
                },
            ],
        )
        step = walkthrough.Step(
            1,
            "Alice",
            "Factory",
            "0x" + "2" * 40,
            "createPool(address)",
            [None],
        )
        ok, reason = walkthrough._validate_step_arguments(step, model)
        self.assertFalse(ok)
        self.assertIn("agreement", reason)
        self.assertIn("IAgreement", reason)

    def test_generic_plan_uses_observed_dependency_argument(self):
        agreement = "0x" + "b" * 40
        actors = [
            walkthrough.Actor("Alice", "0x" + "1" * 40, 0),
            walkthrough.Actor("Bob", "0x" + "2" * 40, 1),
        ]
        model = walkthrough.ContractModel(
            name="Factory",
            source="src/Factory.sol",
            artifact="out/Factory.sol/Factory.json",
            functions=["createPool(address)"],
            abi=[{
                "type":"function","name":"createPool",
                "inputs":[{"name":"agreement","type":"address"}],
                "stateMutability":"nonpayable",
            }],
        )
        recipe = walkthrough.plan_workflow(
            model, actors, "0x"+"3"*40, 100, 1, observed={"agreement": agreement}
        )
        self.assertEqual(recipe[0].args[0], agreement)
        self.assertTrue(recipe[0].inferred)

    def test_auxiliary_project_models_are_available_for_runtime_decoding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "test" / "mocks").mkdir(parents=True)
            (root / "out" / "Demo.sol").mkdir(parents=True)
            (root / "out" / "MockToken.sol").mkdir(parents=True)
            (root / "foundry.toml").write_text(
                '[profile.default]\nsrc = "src"\n',
                encoding="utf-8",
            )
            (root / "src" / "Demo.sol").write_text(
                "pragma solidity ^0.8.20; contract Demo { function ping() external {} }",
                encoding="utf-8",
            )
            (root / "test" / "mocks" / "MockToken.sol").write_text(
                "pragma solidity ^0.8.20; contract MockToken { function transfer(address,uint256) external {} }",
                encoding="utf-8",
            )
            (root / "out" / "Demo.sol" / "Demo.json").write_text(
                json.dumps({
                    "contractName": "Demo",
                    "sourceName": "src/Demo.sol",
                    "abi": [{"type":"function","name":"ping","inputs":[],"outputs":[]}],
                }),
                encoding="utf-8",
            )
            (root / "out" / "MockToken.sol" / "MockToken.json").write_text(
                json.dumps({
                    "contractName": "MockToken",
                    "sourceName": "test/mocks/MockToken.sol",
                    "abi": [{
                        "type":"function","name":"transfer",
                        "inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],
                        "outputs":[{"type":"bool"}],
                    }],
                }),
                encoding="utf-8",
            )
            app_models = walkthrough._artifact_models(root)
            all_models = walkthrough._artifact_models(root, include_aux=True)

        self.assertEqual([item.name for item in app_models], ["Demo"])
        self.assertIn("MockToken", [item.name for item in all_models])

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

    def test_dependency_probe_reports_false_result(self):
        source_model = walkthrough.ContractModel(
            name="Factory",
            source="src/Factory.sol",
            artifact="out/Factory.sol/Factory.json",
            abi=[{
                "type": "function", "name": "createPool",
                "inputs": [{"name": "agreement", "type": "address"}],
                "outputs": [], "stateMutability": "nonpayable",
            }],
            functions=["createPool(address)"],
            calls=[{
                "kind": "cross-contract",
                "from": "createPool",
                "to_contract": "IRegistry",
                "to_function": "isValid",
                "via": "registry",
            }],
        )
        registry = walkthrough.ContractModel(
            name="Registry",
            source="src/Registry.sol",
            artifact="out/Registry.sol/Registry.json",
            abi=[{
                "type": "function", "name": "isValid",
                "inputs": [{"name": "agreement", "type": "address"}],
                "outputs": [{"type": "bool"}], "stateMutability": "view",
            }],
        )
        step = walkthrough.Step(
            1, "Alice", "Factory", "0x" + "1" * 40,
            "createPool(address)", ["0x" + "2" * 40], status="blocked"
        )
        def fake_cmd(args, timeout=8):
            if args[:3] == ["cast", "call", "0x" + "3" * 40]:
                return 0, "false\n", ""
            return 1, "", "not found"
        with patch.object(walkthrough, "_runtime_code", return_value="0x6000"), patch.object(walkthrough, "_cmd", side_effect=fake_cmd):
            origin, rendered = walkthrough._probe_source_dependency_result(
                "http://127.0.0.1:8545", step, source_model,
                source_model.calls[0], "0x" + "3" * 40, [source_model, registry]
            )
        self.assertIn("false", rendered)
        self.assertIn("returned false", origin)


    def test_human_probe_renderer_marks_success_for_review(self):
        model = walkthrough.ContractModel(
            name="DemoPool",
            source="contracts/Demo.vy",
            artifact="build/contracts/Demo.json",
            functions=["setRegistry(address)"],
            function_locations={"setRegistry": 12},
        )
        actors = [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)]
        step = walkthrough.Step(
            1, "Alice", "DemoPool", "0x" + "2" * 40,
            "setRegistry(address)", ["0x" + "3" * 40], status="success",
        )
        rendered = walkthrough._render_adversarial_probe(pathlib.Path("/tmp/project"), step, model, actors)
        joined = "\n".join(rendered)
        self.assertIn("CHECK THIS", joined)
        self.assertIn("accepted by the chain", joined.lower())
        self.assertIn("Vyper", joined)

    def test_human_probe_renderer_is_language_neutral_for_move(self):
        model = walkthrough.ContractModel(
            name="Vault",
            source="sources/vault.move",
            artifact="artifacts/vault.abi.json",
            functions=["withdraw"],
        )
        actors = [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)]
        step = walkthrough.Step(
            1, "Alice", "Vault", "0x" + "2" * 40,
            "withdraw()", [], status="reverted",
            error_reason="guard rejected the call",
            diagnostics=["source guard: signer must match owner"],
        )
        rendered = walkthrough._render_adversarial_probe(pathlib.Path("/tmp/project"), step, model, actors)
        joined = "\n".join(rendered)
        self.assertIn("NORMAL", joined)
        self.assertIn("Move module", joined)
        self.assertNotIn("Solidity contract", joined)

    def test_human_probe_renderer_marks_broken_fixture_as_lab_issue(self):
        model = walkthrough.ContractModel(
            name="Moderator",
            source="src/moderator.vy",
            artifact="build/moderator.json",
            functions=["flag(address)"],
        )
        actors = [walkthrough.Actor("Bob", "0x" + "1" * 40, 0)]
        step = walkthrough.Step(
            1, "Bob", "Moderator", "0x" + "2" * 40,
            "flag(address)", ["0x" + "3" * 40], status="reverted",
            failure_origin="Moderator -> pool points to an address with no contract code",
        )
        rendered = walkthrough._render_adversarial_probe(pathlib.Path("/tmp/project"), step, model, actors)
        joined = "\n".join(rendered)
        self.assertIn("UNKNOWN", joined)
        self.assertIn("cannot prove the exact reason", joined.lower())
        self.assertIn("Moderator -> pool points to an address with no contract code", joined)

    def test_adversarial_test_teaching_renderer_explains_value_invariant(self):
        model = walkthrough.ContractModel(
            name="BountyArena", source="src/BountyArena.sol", artifact="out/BountyArena.sol/BountyArena.json",
            functions=["createbounty(address,uint256)"],
            function_locations={"createbounty": 4},
            abi=[{
                "type":"function", "name":"createbounty", "stateMutability":"payable",
                "inputs":[{"name":"recipient","type":"address"},{"name":"amount","type":"uint256"}],
            }],
            semantics={"createbounty()": {"guards":["require(amount==msg.value, \"attach eth\")"]}},
        )
        actors = [
            walkthrough.Actor("Alice", "0x"+"1"*40, 0),
            walkthrough.Actor("Treasury", "0x"+"2"*40, 1),
        ]
        step = walkthrough.Step(
            1, "Treasury", "BountyArena", "0x"+"3"*40,
            "createbounty(address,uint256)", ["0x"+"1"*40, 1], value_wei=0,
            status="reverted", error_reason="the contract rejected this call under the current on-chain state",
            diagnostics=['source guard: require(amount==msg.value,"attach eth")'],
        )
        rendered = walkthrough._render_adversarial_probe(pathlib.Path("/tmp/project"), step, model, actors)
        joined = "\n".join(rendered)
        self.assertIn("WHAT", joined)
        self.assertIn("RESULT", joined)
        self.assertIn("amount=1", joined)
        self.assertIn("msg.value=0 ETH", joined)
        self.assertIn("Function arguments and transaction value are separate", joined)
        self.assertIn("SOURCE-CORRELATED", joined)



    def test_human_probe_renderer_can_switch_to_technical_view(self):
        model = walkthrough.ContractModel(
            name="Demo",
            source="src/Demo.sol",
            artifact="out/Demo.sol/Demo.json",
            functions=["pause()"],
        )
        actors = [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)]
        step = walkthrough.Step(
            1, "Alice", "Demo", "0x" + "2" * 40,
            "pause()", [], status="success",
        )
        rendered = walkthrough._render_adversarial_probe(
            pathlib.Path("/tmp/project"), step, model, actors, technical=True
        )
        joined = "\n".join(rendered)
        self.assertIn("ACCEPTED", joined)
        self.assertIn("ROLE", joined)

    def test_adversarial_test_renderer_explains_snapshot_isolation(self):
        rendered = walkthrough._render_adversarial_intro(24, ["createbounty(address,uint256): established"])
        joined = "\n".join(rendered)
        self.assertIn("Every probe starts from the same prepared baseline and is restored after the call.", joined)
        self.assertIn("Random probes reset after each call.", joined)
        self.assertIn("These are randomized transaction probes", joined)

    def test_transaction_evidence_requires_assigned_hash_before_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            step = walkthrough.Step(
                1, "Alice", "Fixture", "0x"+"2"*40,
                "ping(uint256)", [7], status="success",
                tx_hash="0x"+"a"*64,
            )
            receipt = {
                "status": "0x1",
                "blockNumber": "0x10",
                "gasUsed": "0x5208",
            }
            with patch.object(walkthrough, "_rpc_call", return_value={
                "from": "0x"+"1"*40,
                "to": "0x"+"2"*40,
                "value": "0x0",
                "nonce": "0x0",
                "gas": "0x100000",
                "input": "0xdeadbeef",
            }):
                path = walkthrough._write_transaction_evidence(root, "http://127.0.0.1:8545", step, receipt)
            self.assertIsNotNone(path)
            self.assertTrue(path.is_file())
            self.assertEqual(path, root / ".audit" / "walkthrough" / "transactions" / (("0x"+"a"*64) + ".html"))
            self.assertIn("LOWKEY // TRANSACTION CONFIRMATION", path.read_text(encoding="utf-8"))

    def test_friendly_renderer_has_no_host_dependency(self):
        actors = [
            walkthrough.Actor("Alice", "0x" + "1" * 40, 0),
            walkthrough.Actor("Bob", "0x" + "2" * 40, 1),
        ]
        self.assertEqual(walkthrough._friendly_arg(actors[0].address, actors), "Alice")
        self.assertEqual(walkthrough._friendly_arg(True, actors), "true")
        self.assertEqual(walkthrough._friendly_arg(False, actors), "false")

    def test_target_from_host_prefers_factory_from_project_system_adapter(self):
        factory = "0x" + "1" * 40
        config = {
            "target": "0x" + "9" * 40,
            "target_contract": "DemoFactory",
            "rpc": "http://127.0.0.1:8545",
            "lab_system": {
                "factory": factory,
                "root": factory,
                "root_model": "DemoFactory",
                "pool": "0x" + "2" * 40,
                "child_model": "DemoPool",
            },
        }

        class Host:
            def anvil_rpc_info(self, _config):
                return {"url": "http://127.0.0.1:8545", "accounts": ["0x" + "a" * 40]}

            def _bind_detected_anvil(self, _config, _info):
                return None

            def discover_local_lab_script(self, _root):
                return None

            def _bootstrap_audit_target(self, _config, _root, allow_deploy=True):
                return _config["target"]

        with patch.object(walkthrough, "_runtime_code", return_value="0x6000"):
            target, contract = walkthrough._target_from_host(
                Host(), config, pathlib.Path("."), None, True
            )
        self.assertEqual(target, factory)
        self.assertEqual(contract, "DemoFactory")

    def test_connection_renderer_explains_factory_lifecycle(self):
        factory = walkthrough.ContractModel(
            name="ConfidencePoolFactory",
            source="src/ConfidencePoolFactory.sol",
            artifact="out/ConfidencePoolFactory.sol/ConfidencePoolFactory.json",
            functions=["createPool(address,address,uint256,uint256,address,address[])"],
            calls=[
                {
                    "kind": "cross-contract",
                    "from": "createPool",
                    "to_contract": "IAgreement",
                    "to_function": "owner",
                    "via": "agreement",
                },
                {
                    "kind": "cross-contract",
                    "from": "createPool",
                    "to_contract": "IBattleChainSafeHarborRegistry",
                    "to_function": "isAgreementValid",
                    "via": "safeHarborRegistry",
                },
                {
                    "kind": "cross-contract",
                    "from": "createPool",
                    "to_contract": "ConfidencePool",
                    "to_function": "initialize",
                    "via": "pool",
                },
            ],
        )
        rendered = walkthrough._render_connections(
            pathlib.Path("/tmp/project"),
            [factory],
            factory,
            enabled=False,
        )
        self.assertIn("checks who owns the Agreement", rendered)
        self.assertIn("asks the Safe Harbor Registry whether the Agreement is valid", rendered)
        self.assertIn("creates a new ConfidencePool clone", rendered)

    def test_system_map_uses_readable_relationship_labels(self):
        runtime = [
            walkthrough.RuntimeContract("0x" + "1" * 40, "Factory", "ConfidencePoolFactory", "system"),
            walkthrough.RuntimeContract(
                "0x" + "2" * 40,
                "Pool",
                "ConfidencePool",
                "CLONE",
                "0x" + "1" * 40,
                1,
                "0x" + "3" * 40,
            ),
        ]
        rendered = walkthrough._render_runtime_graph(runtime, enabled=False)
        self.assertIn("protocol entry point", rendered)
        self.assertIn("creates / clones", rendered)
        self.assertIn("ConfidencePool", rendered)

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

    def test_plan_workflow_avoids_explicit_administrative_controls(self):
        model = walkthrough.ContractModel(
            name="Demo",
            source="src/Demo.sol",
            artifact="out/Demo.sol/Demo.json",
            abi=[
                {"type":"function","name":"setAdmin","inputs":[{"name":"account","type":"address"}],"stateMutability":"nonpayable"},
                {"type":"function","name":"deposit","inputs":[],"stateMutability":"payable"},
            ],
        )
        actors = [walkthrough.Actor("Alice","0x"+"1"*40,0), walkthrough.Actor("Bob","0x"+"2"*40,1)]
        recipe = walkthrough.plan_workflow(model, actors, "0x"+"3"*40, 100, 4)
        self.assertNotIn("setAdmin(address)", [step.function for step in recipe])

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

    def test_actor_rpc_setup_does_not_reset_funded_account(self):
        calls = []

        def rpc(_url, method, params=None):
            calls.append((method, params))
            if method == "eth_getBalance":
                return hex(2 * 10**18)
            return None

        with patch.object(walkthrough, "_rpc_call", side_effect=rpc):
            walkthrough._actor_rpc_setup("http://127.0.0.1:8545", "0x" + "1" * 40)

        methods = [method for method, _params in calls]
        self.assertIn("anvil_impersonateAccount", methods)
        self.assertIn("eth_getBalance", methods)
        self.assertNotIn("anvil_setBalance", methods)


    def test_sol_address_literal_avoids_hex_address_checksum_rule(self):
        raw = "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512"
        literal = walkthrough._sol_address_literal(raw)
        self.assertEqual(
            literal,
            f"address(uint160({int(raw[2:], 16)}))",
        )
        self.assertNotIn(raw, literal)


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
        expected_target = int("70997970c51812dc3a010c7d01b50e0d17dc79c8", 16)
        self.assertIn(f"target_1 = address(uint160({expected_target}));", content)
        self.assertIn('.call{value: 1000000000000000000}(hex"abcdef");', content)
        self.assertIn("bool ok_1", content)
        self.assertNotIn("bool ok, )", content)
        self.assertNotIn("address target_1 = 0x70997970c51812dc3a010c7d01b50e0d17dc79c8;", content)


    def test_actual_call_tree_is_connected(self):
        step = walkthrough.Step(
            1, "Alice", "Factory", "0x" + "1" * 40,
            "createPool()", [], status="success",
        )
        step.execution_edges = [
            {"depth": 0, "to_contract": "Factory", "function": "createPool()"},
            {"depth": 1, "to_contract": "Agreement", "function": "owner()"},
            {"depth": 1, "to_contract": "ConfidencePool", "function": "initialize()"},
            {"depth": 2, "to_contract": "Registry", "function": "isAgreementValid(address)"},
        ]
        actors = [walkthrough.Actor("Alice", "0x" + "a" * 40, 0)]
        rendered = walkthrough._render_actual_call_tree(step, [], False)
        self.assertIn("Alice ──▶ Factory.createPool()", rendered)
        self.assertIn("├─▶ Agreement.owner()", rendered)
        self.assertIn("├─▶ ConfidencePool.initialize()", rendered)
        self.assertIn("Registry.isAgreementValid(address)  ✓", rendered)

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
        self.assertIn("Alice ────▶ Escrow.deposit(Bob)", rendered)
        self.assertIn("sends 1 ETH", rendered)
        self.assertIn("NATIVE VALUE Alice → Bob: 1 ETH", rendered)
        self.assertIn("Alice sends 1 ETH", rendered)
        self.assertIn("fund the escrow for Bob", rendered)
        self.assertIn("WHY THIS STEP: Alice funds the escrow for Bob [LAB CONTROL]", rendered)



    def test_artifact_models_honor_foundry_custom_out_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "forge-artifacts" / "AaveDIVAWrapper.sol").mkdir(parents=True)

            (root / "foundry.toml").write_text(
                '[profile.default]\nsrc = "src"\nout = "forge-artifacts"\n',
                encoding="utf-8",
            )
            (root / "src" / "AaveDIVAWrapper.sol").write_text(
                "pragma solidity ^0.8.20;\ncontract AaveDIVAWrapper {\n"
                "    function owner() external view returns (address) {}\n"
                "}\n",
                encoding="utf-8",
            )
            artifact = {
                "contractName": "AaveDIVAWrapper",
                "sourceName": "src/AaveDIVAWrapper.sol",
                "abi": [
                    {
                        "type": "function",
                        "name": "owner",
                        "inputs": [],
                        "outputs": [{"name": "", "type": "address"}],
                        "stateMutability": "view",
                    }
                ],
            }
            (root / "forge-artifacts" / "AaveDIVAWrapper.sol" / "AaveDIVAWrapper.json").write_text(
                json.dumps(artifact),
                encoding="utf-8",
            )

            models = walkthrough._artifact_models(root)
            self.assertTrue(any(model.name == "AaveDIVAWrapper" for model in models))
            model = next(model for model in models if model.name == "AaveDIVAWrapper")
            self.assertEqual(model.artifact, "forge-artifacts/AaveDIVAWrapper.sol/AaveDIVAWrapper.json")
            self.assertIn("owner()", model.functions)


    def test_cli_arg_renders_tuples_and_tuple_arrays_for_cast(self):
        tuple_param = {
            "type": "tuple",
            "components": [
                {"type": "address"},
                {"type": "uint256"},
            ],
        }
        self.assertEqual(
            walkthrough._cli_arg(
                ["0x" + "1" * 40, 7],
                tuple_param,
            ),
            "(0x" + "1" * 40 + ",7)",
        )

        tuple_array_param = {
            "type": "tuple[]",
            "components": [
                {"type": "address"},
                {"type": "uint256"},
            ],
        }
        self.assertEqual(
            walkthrough._cli_arg(
                [["0x" + "1" * 40, 7], ["0x" + "2" * 40, 8]],
                tuple_array_param,
            ),
            "[(0x" + "1" * 40 + ",7),(0x" + "2" * 40 + ",8)]",
        )

    def test_adversarial_probe_without_arguments_does_not_duplicate_function_parentheses(self):
        model = walkthrough.ContractModel(
            name="Demo",
            source="src/Demo.sol",
            artifact="out/Demo.sol/Demo.json",
            abi=[{
                "type": "function",
                "name": "ping",
                "inputs": [],
                "outputs": [],
                "stateMutability": "nonpayable",
            }],
            functions=["ping()"],
            function_locations={"ping": 3},
        )
        step = walkthrough.Step(
            1,
            "Alice",
            "Demo",
            "0x" + "1" * 40,
            "ping()",
            [],
            status="success",
        )
        rendered = walkthrough._render_adversarial_probe_human(
            pathlib.Path("/tmp/project"),
            step,
            model,
            [walkthrough.Actor("Alice", "0x" + "2" * 40, 0)],
        )
        self.assertTrue(any("Demo.ping()" in line for line in rendered))
        self.assertFalse(any("Demo.ping()()" in line for line in rendered))

    def test_replay_story_builds_source_guided_setup_before_repeating_payout(self):
        model = walkthrough.ContractModel(
            name="Escrow",
            source="src/Escrow.sol",
            artifact="out/Escrow.sol/Escrow.json",
            abi=[
                {
                    "type": "function",
                    "name": "createescrow",
                    "inputs": [
                        {"name": "amount", "type": "uint256"},
                        {"name": "recipient", "type": "address"},
                    ],
                    "outputs": [],
                    "stateMutability": "payable",
                },
                {
                    "type": "function",
                    "name": "acceptescrow",
                    "inputs": [{"name": "accept", "type": "bool"}],
                    "outputs": [],
                    "stateMutability": "nonpayable",
                },
                {
                    "type": "function",
                    "name": "release",
                    "inputs": [],
                    "outputs": [],
                    "stateMutability": "nonpayable",
                },
            ],
            functions=["createescrow(uint256,address)", "acceptescrow(bool)", "release()"],
        )
        actor = walkthrough.Actor("Attacker", "0x" + "1" * 40, 2)
        stories = walkthrough_finding_patterns._build_replay_stories(
            {},
            [actor],
            [("Escrow", "0x" + "2" * 40, model)],
            123,
        )
        self.assertEqual(len(stories), 1)
        self.assertEqual([action.get("function") for action in stories[0].actions if action.get("kind") == "call"],
                         ["createescrow(uint256,address)", "acceptescrow(bool)", "release()", "release()"])
        reserve = next(action for action in stories[0].actions if action.get("kind") == "fund_target")
        self.assertEqual(reserve["amount"], 2)
        self.assertEqual(reserve["address"], "0x" + "2" * 40)
        self.assertEqual(stories[0].actions[0]["actor"], "Attacker")
        self.assertEqual(stories[0].actions[0]["args"][1], actor.address)
        self.assertEqual(stories[0].actions[0]["value"], 1)

    def test_replay_story_blocks_when_lifecycle_setup_is_unavailable(self):
        model = walkthrough.ContractModel(
            name="Demo",
            source="src/Demo.sol",
            artifact="out/Demo.sol/Demo.json",
            abi=[{
                "type": "function",
                "name": "release",
                "inputs": [],
                "outputs": [],
                "stateMutability": "nonpayable",
            }],
            functions=["release()"],
        )
        actor = walkthrough.Actor("Attacker", "0x" + "1" * 40, 2)
        stories = walkthrough_finding_patterns._build_replay_stories(
            {},
            [actor],
            [("Demo", "0x" + "2" * 40, model)],
            123,
        )
        self.assertEqual(stories[0].signal, "BLOCKED")
        self.assertEqual(stories[0].actions, [])

    def test_replay_story_maps_live_evidence_to_repeated_payout_target(self):
        story = walkthrough_finding_patterns.core.WalkthroughStory(
            story_id="RP-01",
            title="Replay probe",
            goal="repeat payout",
            actions=[],
        )
        setup = walkthrough.Step(1, "Attacker", "Escrow", "0x" + "2" * 40, "createescrow(uint256,address)", [])
        first = walkthrough.Step(2, "Attacker", "Escrow", "0x" + "2" * 40, "release()", [])
        second = walkthrough.Step(3, "Attacker", "Escrow", "0x" + "2" * 40, "release()", [])
        self.assertIs(walkthrough_finding_patterns._observation_step_for_story(story, [setup, first, second]), first)


    def test_replay_story_assessment_uses_last_two_steps_after_setup(self):
        actor = walkthrough.Actor("Attacker", "0x" + "1" * 40, 2)
        story = walkthrough_finding_patterns.core.WalkthroughStory(
            story_id="RP-01",
            title="Replay probe",
            goal="repeat payout",
            actions=[
                {"function": "createescrow(uint256,address)"},
                {"function": "acceptescrow(bool)"},
                {"function": "release()"},
                {"function": "release()"},
            ],
        )
        setup = [
            walkthrough.Step(1, "Attacker", "Escrow", "0x" + "2" * 40, "createescrow(uint256,address)", [1, actor.address], value_wei=1, status="success"),
            walkthrough.Step(2, "Attacker", "Escrow", "0x" + "2" * 40, "acceptescrow(bool)", [True], status="success"),
        ]
        first = walkthrough.Step(3, "Attacker", "Escrow", "0x" + "2" * 40, "release()", [], status="success")
        second = walkthrough.Step(4, "Attacker", "Escrow", "0x" + "2" * 40, "release()", [], status="success")
        key = actor.address.lower()
        first.balance_after = {key: 101}
        first.balance_before = {key: 100}
        second.balance_after = {key: 102}
        second.balance_before = {key: 101}
        walkthrough_finding_patterns.assess_replay_story(
            story, setup + [first, second], [actor]
        )
        self.assertEqual(story.signal, "CONFIRMED")

    def test_record_walkthrough_latest_persists_successful_concrete_call(self):
        calls = []

        class Context:
            def set_latest(self, root, **kwargs):
                calls.append((root, kwargs))

        class Host:
            audit_context = Context()

        step = walkthrough.Step(
            1,
            "Alice",
            "Escrow",
            "0x" + "2" * 40,
            "acceptescrow(bool)",
            [True],
            value_wei=0,
            status="success",
            tx_hash="0x" + "a" * 64,
            calldata="0x5c36b186" + "0" * 63 + "1",
        )
        root = pathlib.Path("/tmp/project")
        walkthrough._record_walkthrough_latest(Host(), root, step)

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], root)
        self.assertEqual(calls[0][1]["function"], "acceptescrow(bool)")
        self.assertEqual(calls[0][1]["calldata"], "0x5c36b186" + "0" * 63 + "1")
        self.assertEqual(calls[0][1]["tx_hash"], "0x" + "a" * 64)


    def test_walkthrough_actors_use_configured_profiles_and_do_not_fabricate_treasury(self):
        class Host:
            def anvil_rpc_info(self, config):
                return {'accounts': [
                    '0x' + '1' * 40,
                    '0x' + '2' * 40,
                    '0x' + '3' * 40,
                    '0x' + '4' * 40,
                ]}

        addresses = ['0x' + str(i) * 40 for i in range(1, 5)]
        config = {
            'wallets': {
                'Alice': {'source': 'anvil-default', 'anvil_index': 0, 'address': addresses[0]},
                'Bob': {'source': 'anvil-default', 'anvil_index': 1, 'address': addresses[1]},
                'Attacker': {'source': 'anvil-default', 'anvil_index': 2, 'address': addresses[2]},
                'lab-deployer': {'source': 'anvil-default', 'anvil_index': 0, 'address': addresses[0], 'internal': True},
            }
        }
        actors = walkthrough._actors(Host(), config, 4)
        self.assertEqual([actor.name for actor in actors], ['Alice', 'Bob', 'Attacker', 'Anvil #3'])
        self.assertNotIn('Treasury', [actor.name for actor in actors])


    def test_adversarial_human_view_shows_actual_call_arguments(self):
        model = walkthrough.ContractModel(
            name="Escrow",
            source="src/EthEscrow.sol",
            artifact="out/EthEscrow.sol/Escrow.json",
            abi=[{
                "type": "function",
                "name": "acceptescrow",
                "inputs": [{"name": "accept", "type": "bool"}],
                "outputs": [],
                "stateMutability": "nonpayable",
            }],
            functions=["acceptescrow(bool)"],
            function_locations={"acceptescrow": 43},
            semantics={"acceptescrow()": {"guards": ['require(accept, "rejected")']}},
        )
        step = walkthrough.Step(
            6,
            "Bob",
            "Escrow",
            "0x" + "3" * 40,
            "acceptescrow(bool)",
            [False],
            status="reverted",
        )
        actors = [
            walkthrough.Actor("Alice", "0x" + "1" * 40, 0),
            walkthrough.Actor("Bob", "0x" + "2" * 40, 1),
        ]
        rendered = walkthrough._render_adversarial_probe_human(
            pathlib.Path("/tmp/project"), step, model, actors
        )
        joined = "\n".join(rendered)
        self.assertIn("Escrow.acceptescrow(false)", joined)
        self.assertIn("source requires accept == true", joined)
        self.assertIn("SOURCE + ACTUAL CALL", joined)


    
    def test_event_rows_normalize_legacy_decoder_tuple(self):
        class Host:
            def decode_event_log(self, _config, _log):
                return (
                    "CreateEscrow(uint256,address)",
                    "Event: CreateEscrow(uint256,address)\\nIndexed amount: 1\\nIndexed creator: Bob",
                )

        receipt = {
            "logs": [{
                "address": "0x" + "3" * 40,
                "topics": ["0x" + "4" * 64],
                "data": "0x",
            }]
        }
        rows = walkthrough._event_rows(Host(), {}, receipt)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event"], "CreateEscrow(uint256,address)")
        self.assertIn("Indexed amount: 1", rows[0]["decoded"])
        self.assertIn("topics", rows[0])
        self.assertIn("data", rows[0])

    def test_trace_edges_fall_back_to_structured_call_trace(self):
        trace = {
            "type": "CALL",
            "to": "0x" + "1" * 40,
            "value": "0xde0b6b3a7640000",
            "calls": [{
                "type": "CALL",
                "to": "0x" + "2" * 40,
                "value": "0x0",
            }],
        }
        with patch.object(walkthrough, "_cmd", return_value=(1, "", "cast run unavailable")):
            edges = walkthrough._trace_edges("http://127.0.0.1:8545", "0x" + "a" * 64, trace)
        self.assertEqual(len(edges), 2)
        self.assertIn("value=1000000000000000000 wei", edges[0])

    def test_execution_call_tree_renders_internal_eth_value_without_duplicate_root_path(self):
        step = walkthrough.Step(
            1,
            "Alice",
            "Escrow",
            "0x" + "3" * 40,
            "release()",
            [],
            status="success",
        )
        step.execution_edges = [
            {
                "depth": 0,
                "to_contract": "Escrow",
                "to_address": step.address,
                "function": "release()",
                "value_wei": 0,
            },
            {
                "depth": 1,
                "to_contract": "Bob",
                "to_address": "0x" + "2" * 40,
                "function": "CALL",
                "value_wei": 10**18,
            },
        ]
        rendered = walkthrough._render_interaction_graph(
            step,
            [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)],
            False,
        )
        self.assertIn("LIVE CALL CHAIN", rendered)
        self.assertIn("Escrow.release()", rendered)
        self.assertIn("1 ETH", rendered)
        self.assertNotIn("ACTUAL RUNTIME PATH", rendered)

    def test_empty_change_report_distinguishes_unobserved_from_no_change(self):
        step = walkthrough.Step(
            1,
            "Alice",
            "Escrow",
            "0x" + "3" * 40,
            "release()",
            [],
            status="success",
        )
        step.execution_edges = [{
            "depth": 1,
            "to_contract": "Bob",
            "to_address": "0x" + "2" * 40,
            "function": "CALL",
            "value_wei": 10**18,
        }]
        rendered = walkthrough._render_interaction_graph(
            step,
            [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)],
            False,
        )
        self.assertIn("storage: not observed", rendered)
        self.assertIn("native balances: not observed", rendered)
        self.assertIn("runtime call trace carried 1 ETH [1,000,000,000,000,000,000 wei], but no tracked native-balance delta was recorded", rendered)

    def test_system_workflow_uses_live_target_relation_even_when_model_matching_is_external(self):
        target = "0x" + "9" * 40
        model = walkthrough.ContractModel(
            name="Escrow",
            source="src/EthEscrow.sol",
            artifact="out/EthEscrow.sol/Escrow.json",
        )
        runtime = [
            walkthrough.RuntimeContract(
                target, "External", "Escrow", "target"
            )
        ]
        rendered = walkthrough._render_system_workflow_graph(
            pathlib.Path("/tmp/project"),
            [model],
            runtime,
            model,
            False,
        )
        self.assertIn("Escrow", rendered)
        self.assertIn("0x99999999…99999999", rendered)
        self.assertNotIn("not live", rendered)
        self.assertIn("source relationships: none resolved", rendered)

    def test_withdraw_flow_is_labeled_native_eth_when_trace_carries_eth(self):
        step = walkthrough.Step(
            1,
            "Alice",
            "Fallback",
            "0x" + "3" * 40,
            "withdraw()",
            [],
            status="success",
        )
        step.execution_edges = [{
            "depth": 1,
            "to_contract": "Alice",
            "to_address": "0x" + "1" * 40,
            "function": "CALL",
            "value_wei": 2,
        }]
        rendered = walkthrough._render_interaction_graph_full(
            pathlib.Path("/tmp/project"),
            step,
            [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)],
            walkthrough.ContractModel(name="Fallback", source="src/Fallback.sol", artifact="out/Fallback.sol/Fallback.json"),
            [],
            False,
            [],
        )
        self.assertIn("native ETH flow: Fallback ──▶ Alice", rendered)
        self.assertNotIn("token flow: Fallback ──▶ Alice", rendered)

    def test_native_value_flow_separates_gas_from_protocol_value(self):
        step = walkthrough.Step(
            1,
            "Alice",
            "Escrow",
            "0x" + "3" * 40,
            "release()",
            [],
            status="success",
        )
        alice = "0x" + "1" * 40
        escrow = "0x" + "3" * 40
        bob = "0x" + "2" * 40
        step.balance_before = {
            alice.lower(): 100 * 10**18,
            escrow.lower(): 5 * 10**18,
            bob.lower(): 0,
        }
        step.balance_after = {
            alice.lower(): 98 * 10**18,
            escrow.lower(): 4 * 10**18,
            bob.lower(): 1 * 10**18,
        }
        step.gas_cost_wei = 2 * 10**18
        actors = [
            walkthrough.Actor("Alice", alice, 0),
            walkthrough.Actor("Bob", bob, 1),
        ]
        lines = walkthrough._friendly_gas_lines(step) + walkthrough._friendly_balance_lines(step, actors, [])
        self.assertTrue(any(line.startswith("GAS COST Alice: -2 ETH") for line in lines))
        self.assertTrue(any(line.startswith("NATIVE VALUE Escrow → Bob: 1 ETH") for line in lines))
        self.assertNotIn("NATIVE BALANCE Alice", lines)

    def test_system_workflow_legend_does_not_call_source_relationship_observed_live(self):
        model = walkthrough.ContractModel(
            name="Escrow",
            source="src/EthEscrow.sol",
            artifact="out/EthEscrow.sol/Escrow.json",
        )
        runtime = [
            walkthrough.RuntimeContract(
                "0x" + "9" * 40, "External", "Escrow", "target"
            )
        ]
        rendered = walkthrough._render_system_workflow_graph(
            pathlib.Path("/tmp/project"),
            [model],
            runtime,
            model,
            False,
        )
        self.assertIn("source relationships: none resolved", rendered)
        self.assertIn("live execution: observed in the protocol story", rendered)
        self.assertNotIn("source relationship   ● observed live", rendered)

    def test_live_latest_step_is_not_marked_as_review(self):
        model = walkthrough.ContractModel(
            name="Escrow",
            source="src/EthEscrow.sol",
            artifact="out/EthEscrow.sol/Escrow.json",
        )
        step = walkthrough.Step(
            1,
            "Alice",
            "Escrow",
            "0x" + "3" * 40,
            "release()",
            [],
            status="success",
        )
        rendered = walkthrough._render_protocol_story_full(
            pathlib.Path("/tmp/project"),
            [step],
            step,
            [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)],
            [model],
            False,
        )
        self.assertIn("NOW  •  LIVE", rendered)
        self.assertNotIn("REVIEWING  •  FUNCTION 01", rendered)

    def test_review_mode_marks_latest_step_as_review_and_not_live(self):
        model = walkthrough.ContractModel(
            name="Escrow",
            source="src/EthEscrow.sol",
            artifact="out/EthEscrow.sol/Escrow.json",
        )
        step = walkthrough.Step(
            1,
            "Alice",
            "Escrow",
            "0x" + "3" * 40,
            "release()",
            [],
            status="success",
        )
        rendered = walkthrough._render_protocol_story_full(
            pathlib.Path("/tmp/project"),
            [step],
            step,
            [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)],
            [model],
            False,
            review_mode=True,
        )
        self.assertIn("REVIEWING  •  FUNCTION 01  •  OBSERVED", rendered)
        self.assertIn("ENTER = return to the next live interaction", rendered)
        self.assertNotIn("NOW  •  LIVE", rendered)

    def test_success_step_exposes_evidence_basis(self):
        step = walkthrough.Step(
            1,
            "Alice",
            "Escrow",
            "0x" + "3" * 40,
            "release()",
            [],
            reason="release after acceptance",
            status="success",
        )
        rendered = walkthrough._render_interaction_graph(
            step,
            [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)],
            False,
        )
        self.assertIn("BASIS: source-guided candidate passed live preflight and was confirmed on-chain", rendered)

    def test_forge_storage_layout_fallback_reads_json_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\\nsrc = \"src\"\\n", encoding="utf-8")
            payload = {"storage": [{"label": "escrow", "slot": "0"}], "types": {}}
            with patch.object(walkthrough.shutil, "which", return_value="/usr/bin/forge"), patch.object(
                walkthrough,
                "_cmd",
                return_value=(0, json.dumps(payload), ""),
            ) as mocked:
                result = walkthrough._forge_storage_layout(root, "Escrow")
            self.assertEqual(result, payload)
            mocked.assert_called_once()
            self.assertEqual(
                mocked.call_args.args[0],
                ["forge", "inspect", "--json", "Escrow", "storage-layout"],
            )
    

    def test_snapshot_runtime_recovers_missing_storage_layout_and_mapping_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            model = walkthrough.ContractModel(
                name="Fallback",
                source="src/Fallback.sol",
                artifact="out/Fallback.sol/Fallback.json",
                storage={},
            )
            runtime = [
                walkthrough.RuntimeContract(
                    "0x" + "3" * 40,
                    "Fallback",
                    "Fallback",
                    "target",
                )
            ]
            key = "0x" + "1" * 40
            mapped_slot = "0x" + "2" * 64
            layout = {
                "storage": [{
                    "label": "contributions",
                    "slot": "0",
                    "type": "t_mapping",
                }],
                "types": {
                    "t_mapping": {
                        "label": "mapping(address => uint256)",
                        "encoding": "mapping",
                        "key": "t_address",
                        "value": "t_uint256",
                    },
                    "t_address": {
                        "label": "address",
                        "encoding": "inplace",
                        "numberOfBytes": 20,
                    },
                    "t_uint256": {
                        "label": "uint256",
                        "encoding": "inplace",
                        "numberOfBytes": 32,
                    },
                },
            }
            def fake_cmd(args, cwd=None, timeout=30):
                self.assertEqual(args[:2], ["cast", "index"])
                return 0, mapped_slot + "\n", ""
            with patch.object(walkthrough, "_forge_storage_layout", return_value=layout), \
                 patch.object(walkthrough, "_cmd", side_effect=fake_cmd), \
                 patch.object(walkthrough, "_storage_read", return_value="0x" + "0" * 63 + "1"):
                result = walkthrough._snapshot_runtime(
                    runtime,
                    [model],
                    "http://127.0.0.1:8545",
                    [key],
                    observed_keys=[],
                    root=root,
                )

            self.assertEqual(len(result), 1)
            self.assertEqual(model.storage, layout)
            self.assertEqual(result[0]["label"], "contributions")
            self.assertEqual(result[0]["mapping"]["rows"][0]["key"], key)
            self.assertEqual(result[0]["mapping"]["rows"][0]["slot"], mapped_slot)
            self.assertEqual(result[0]["mapping"]["rows"][0]["value"], 1)


    def test_replay_assessment_rejects_isolated_probe_repeatability(self):
        story = walkthrough.WalkthroughStory(
            story_id="RP-ISO",
            title="Replay probe",
            goal="repeat payout",
            actions=[{"function": "release()"}, {"function": "release()"}],
            execution_scope="isolated_probe",
            reset_between_actions=True,
        )
        actor = walkthrough.Actor("Attacker", "0x" + "1" * 40, 2)
        first = walkthrough.Step(
            1, actor.name, "Escrow", "0x" + "2" * 40, "release()", [], status="success",
        )
        second = walkthrough.Step(
            2, actor.name, "Escrow", "0x" + "2" * 40, "release()", [], status="success",
        )
        walkthrough_finding_patterns.assess_replay_story(story, [first, second], [actor])
        self.assertEqual(story.signal, "BLOCKED")
        self.assertIn("repeatability, not replay evidence", " ".join(story.evidence))

    def test_replay_assessment_uses_internal_eth_transfer_not_net_eoa_balance(self):
        story = walkthrough.WalkthroughStory(
            story_id="RP-TRACE",
            title="Replay probe",
            goal="repeat payout",
            actions=[{"function": "release()"}, {"function": "release()"}],
            execution_scope="persistent_story",
            reset_between_actions=False,
        )
        actor = walkthrough.Actor("Attacker", "0x" + "1" * 40, 2)
        target = "0x" + "2" * 40
        setup = walkthrough.Step(
            1, actor.name, "Escrow", target, "createescrow(uint256,address)",
            [1, actor.address], value_wei=1, status="success",
        )
        first = walkthrough.Step(
            2, actor.name, "Escrow", target, "release()", [], status="success",
        )
        second = walkthrough.Step(
            3, actor.name, "Escrow", target, "release()", [], status="success",
        )
        second.balance_before = {actor.address.lower(): 10**18}
        second.balance_after = {actor.address.lower(): 10**18 - 200000}
        second.execution_edges = [{
            "depth": 1,
            "to_address": actor.address,
            "to_contract": actor.name,
            "function": "CALL",
            "value_wei": 1,
        }]
        walkthrough_finding_patterns.assess_replay_story(
            story, [setup, first, second], [actor]
        )
        self.assertEqual(story.signal, "CONFIRMED")
        self.assertIn("1 wei", " ".join(story.evidence))

    def test_owner_mismatch_with_legitimate_eoa_recipient_is_normal(self):
        step = walkthrough.Step(
            1,
            "Attacker",
            "Fallback",
            "0x" + "3" * 40,
            "withdraw()",
            [],
            status="reverted",
        )
        step.failure_origin = "Fallback.owner() does not match Attacker"
        step.diagnostics = [
            "owner = 0x" + "1" * 40 + " is an EOA (wallet address); transfer() can send native ETH to wallets without contract code",
            "✕ owner() = 0x" + "1" * 40 + "; caller is Attacker",
        ]
        status, _, _ = walkthrough._human_probe_status(step)
        self.assertEqual(status, "✅ NORMAL")

    def test_owner_mismatch_explanation_does_not_claim_target_argument_bypass(self):
        step = walkthrough.Step(
            1,
            "Bob",
            "Fallback",
            "0x" + "3" * 40,
            "withdraw()",
            [],
            status="reverted",
        )
        step.diagnostics = ["✕ owner() = 0x" + "1" * 40 + "; caller is Bob"]
        why, lesson, quality = walkthrough._adversarial_probe_why(
            step,
            walkthrough.ContractModel(
                name="Fallback",
                source="src/Fallback.sol",
                artifact="out/Fallback.sol/Fallback.json",
            ),
            [],
        )
        self.assertIn("owner-only authorization check", why)
        self.assertIn("msg.sender", lesson)
        self.assertNotIn("target argument", lesson)
        self.assertEqual(quality, "SOURCE-CORRELATED")

    def test_pattern_summary_distinguishes_static_candidates_from_live_upgrades(self):
        obs = [
            walkthrough_finding_patterns.PatternObservation(
                pattern_id="REPLAY-001",
                title="Replayable payout / claim path",
                status="REVIEW",
                contract="Fallback",
                function="withdraw",
                source="src/Fallback.sol",
                line=30,
            )
        ]
        rendered = "\n".join(walkthrough_finding_patterns.render_summary(obs))
        self.assertIn("STATIC CANDIDATES  0", rendered)
        self.assertIn("LIVE-UPGRADED     1", rendered)
        self.assertIn("SOURCE PATTERN MATCHES", rendered)
        self.assertNotIn("STATIC MATCHES", rendered)

    def test_seed_history_renders_recorded_runs_and_replay_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            path = walkthrough._seed_history_path(root)
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps([
                {
                    "run_id": "demo-12345",
                    "timestamp": "2026-10-02 14:00:00",
                    "seed": 12345,
                    "cases": 24,
                    "target": "0x" + "1" * 40,
                    "contract": "Demo",
                    "accepted": 18,
                    "reverted": 6,
                    "highlights": [
                        "chain accepted: withdraw, transfer",
                        "finding patterns to review: REPLAY-001",
                    ],
                }
            ]), encoding="utf-8")
            rendered = io.StringIO()
            with patch("sys.stdout", rendered):
                code = walkthrough._render_seed_history(root)
            output = rendered.getvalue()
            self.assertEqual(code, 0)
            self.assertIn("SEED 12345", output)
            self.assertIn("24 probes", output)
            self.assertIn("chain accepted: withdraw, transfer", output)
            self.assertIn("REPLAY-001", output)
            self.assertIn("lk walkthrough test --seed 12345 --cases 24", output)

    def test_seed_history_can_filter_one_seed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            path = walkthrough._seed_history_path(root)
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps([
                {"seed": 111, "cases": 10, "timestamp": "t1", "contract": "Demo", "accepted": 10, "reverted": 0, "highlights": ["all normal"]},
                {"seed": 222, "cases": 20, "timestamp": "t2", "contract": "Demo", "accepted": 15, "reverted": 5, "highlights": ["chain accepted: withdraw"]},
            ]), encoding="utf-8")
            rendered = io.StringIO()
            with patch("sys.stdout", rendered):
                code = walkthrough._render_seed_history(root, "222")
            output = rendered.getvalue()
            self.assertEqual(code, 0)
            self.assertIn("SEED 222", output)
            self.assertNotIn("SEED 111", output)

    def test_adversarial_intro_explains_seed_reproducibility(self):
        intro = "\n".join(walkthrough._render_adversarial_intro(24, []))
        self.assertIn("seed", intro.lower())
        self.assertIn("randomized order, actors, arguments, and test inputs", intro)
        self.assertIn("reuse it with --seed", intro)

    def test_adversarial_output_calls_randomized_executions_probes(self):
        intro = "\n".join(
            walkthrough._render_adversarial_intro(24, [])
        )
        self.assertIn("Running 24 probes", intro)
        summary = "\n".join(
            walkthrough._render_adversarial_summary(
                pathlib.Path("/tmp/project"),
                [
                    walkthrough.Step(
                        1, "Alice", "Demo", "0x" + "2" * 40,
                        "ping()", [], status="success"
                    )
                ],
                pathlib.Path("/tmp/project/.audit/walkthrough/test.json"),
                [],
            )
        )
        self.assertIn("1 probes finished", summary)
        self.assertNotIn("checks finished", summary)

    def test_adversarial_summary_groups_identical_restored_probe_observations(self):
        first = walkthrough.Step(
            1, "Alice", "Fallback", "0x" + "2" * 40, "withdraw()", [], status="success"
        )
        second = walkthrough.Step(
            2, "Alice", "Fallback", "0x" + "2" * 40, "withdraw()", [], status="success"
        )
        rendered = "\n".join(
            walkthrough._render_adversarial_summary(
                pathlib.Path("/tmp/project"),
                [first, second],
                pathlib.Path("/tmp/project/.audit/walkthrough/test.json"),
                [],
            )
        )
        self.assertIn("2 probes finished", rendered)
        self.assertIn("1 unique probe outcomes", rendered)
        self.assertIn("repeated in probes #2", rendered)

    def test_replay_assessment_rejects_isolated_probe_repeatability(self):
        story = walkthrough.WalkthroughStory(
            story_id="RP-ISO",
            title="Replay probe",
            goal="repeat payout",
            actions=[{"function": "release()"}, {"function": "release()"}],
            execution_scope="isolated_probe",
            reset_between_actions=True,
        )
        actor = walkthrough.Actor("Attacker", "0x" + "1" * 40, 2)
        first = walkthrough.Step(
            1, actor.name, "Escrow", "0x" + "2" * 40, "release()", [], status="success"
        )
        second = walkthrough.Step(
            2, actor.name, "Escrow", "0x" + "2" * 40, "release()", [], status="success"
        )
        walkthrough_finding_patterns.assess_replay_story(story, [first, second], [actor])
        self.assertEqual(story.signal, "BLOCKED")
        self.assertIn("repeatability, not replay evidence", " ".join(story.evidence))

    def test_replay_assessment_uses_internal_eth_transfer_not_net_eoa_balance(self):
        story = walkthrough.WalkthroughStory(
            story_id="RP-TRACE",
            title="Replay probe",
            goal="repeat payout",
            actions=[{"function": "release()"}, {"function": "release()"}],
            execution_scope="persistent_story",
            reset_between_actions=False,
        )
        actor = walkthrough.Actor("Attacker", "0x" + "1" * 40, 2)
        target = "0x" + "2" * 40
        setup = walkthrough.Step(
            1, actor.name, "Escrow", target, "createescrow(uint256,address)",
            [1, actor.address], value_wei=1, status="success"
        )
        first = walkthrough.Step(
            2, actor.name, "Escrow", target, "release()", [], status="success"
        )
        second = walkthrough.Step(
            3, actor.name, "Escrow", target, "release()", [], status="success"
        )
        second.balance_before = {actor.address.lower(): 10**18}
        second.balance_after = {actor.address.lower(): 10**18 - 200000}
        second.execution_edges = [{
            "depth": 1,
            "to_address": actor.address,
            "to_contract": actor.name,
            "function": "CALL",
            "value_wei": 1,
        }]
        walkthrough_finding_patterns.assess_replay_story(
            story, [setup, first, second], [actor]
        )
        self.assertEqual(story.signal, "CONFIRMED")
        self.assertIn("1 wei", " ".join(story.evidence))

    def test_owner_mismatch_with_legitimate_eoa_recipient_is_normal(self):
        step = walkthrough.Step(
            1, "Attacker", "Fallback", "0x" + "3" * 40, "withdraw()", [], status="reverted"
        )
        step.failure_origin = "Fallback.owner() does not match Attacker"
        step.diagnostics = [
            "owner = 0x" + "1" * 40 + " is an EOA (wallet address); transfer() can send native ETH to wallets without contract code",
            "✕ owner() = 0x" + "1" * 40 + "; caller is Attacker",
        ]
        status, _, _ = walkthrough._human_probe_status(step)
        self.assertEqual(status, "✅ NORMAL")

    def test_owner_mismatch_explanation_does_not_claim_target_argument_bypass(self):
        step = walkthrough.Step(
            1, "Bob", "Fallback", "0x" + "3" * 40, "withdraw()", [], status="reverted"
        )
        step.diagnostics = ["✕ owner() = 0x" + "1" * 40 + "; caller is Bob"]
        why, lesson, quality = walkthrough._adversarial_probe_why(
            step,
            walkthrough.ContractModel(
                name="Fallback",
                source="src/Fallback.sol",
                artifact="out/Fallback.sol/Fallback.json",
            ),
            [],
        )
        self.assertIn("owner-only authorization check", why)
        self.assertIn("msg.sender", lesson)
        self.assertNotIn("target argument", lesson)
        self.assertEqual(quality, "SOURCE-CORRELATED")

    def test_pattern_summary_distinguishes_static_candidates_from_live_upgrades(self):
        obs = [
            walkthrough_finding_patterns.PatternObservation(
                pattern_id="REPLAY-001",
                title="Replayable payout / claim path",
                status="REVIEW",
                contract="Fallback",
                function="withdraw",
                source="src/Fallback.sol",
                line=30,
            )
        ]
        rendered = "\n".join(walkthrough_finding_patterns.render_summary(obs))
        self.assertIn("STATIC CANDIDATES  0", rendered)
        self.assertIn("LIVE-UPGRADED     1", rendered)
        self.assertIn("SOURCE PATTERN MATCHES", rendered)
        self.assertNotIn("STATIC MATCHES", rendered)

    def test_adversarial_output_calls_randomized_executions_probes(self):
        intro = "\n".join(walkthrough._render_adversarial_intro(24, []))
        self.assertIn("Running 24 probes", intro)
        summary = "\n".join(
            walkthrough._render_adversarial_summary(
                pathlib.Path("/tmp/project"),
                [walkthrough.Step(1, "Alice", "Demo", "0x" + "2" * 40, "ping()", [], status="success")],
                pathlib.Path("/tmp/project/.audit/walkthrough/test.json"),
                [],
            )
        )
        self.assertIn("1 probes finished", summary)
        self.assertNotIn("checks finished", summary)

    def test_adversarial_summary_groups_identical_restored_probe_observations(self):
        first = walkthrough.Step(
            1, "Alice", "Fallback", "0x" + "2" * 40, "withdraw()", [], status="success"
        )
        second = walkthrough.Step(
            2, "Alice", "Fallback", "0x" + "2" * 40, "withdraw()", [], status="success"
        )
        rendered = "\n".join(
            walkthrough._render_adversarial_summary(
                pathlib.Path("/tmp/project"),
                [first, second],
                pathlib.Path("/tmp/project/.audit/walkthrough/test.json"),
                [],
            )
        )
        self.assertIn("2 probes finished", rendered)
        self.assertIn("1 unique probe outcomes", rendered)
        self.assertIn("repeated in probes #2", rendered)



    def test_source_guard_accepts_eoa_for_native_transfer_without_lab_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            source = """
            pragma solidity ^0.8.20;
            contract FallbackLike {
                address payable public owner;
                modifier onlyOwner() {
                    require(msg.sender == owner);
                    _;
                }
                function withdraw() external onlyOwner {
                    owner.transfer(address(this).balance);
                }
            }
            """
            (root / "src" / "FallbackLike.sol").write_text(source, encoding="utf-8")
            model = walkthrough.ContractModel(
                name="FallbackLike",
                source="src/FallbackLike.sol",
                artifact="out/FallbackLike.sol/FallbackLike.json",
                abi=[
                    {
                        "type": "function",
                        "name": "withdraw",
                        "inputs": [],
                        "outputs": [],
                        "stateMutability": "nonpayable",
                    },
                    {
                        "type": "function",
                        "name": "owner",
                        "inputs": [],
                        "outputs": [{"type": "address"}],
                        "stateMutability": "view",
                    },
                ],
                functions=["withdraw()"],
            )
            step = walkthrough.Step(
                1,
                "Attacker",
                "FallbackLike",
                "0x" + "3" * 40,
                "withdraw()",
                [],
                status="reverted",
            )
            owner = "0x" + "1" * 40
            edge = {
                "kind": "cross-contract",
                "from": "withdraw",
                "to_contract": "address",
                "to_function": "transfer",
                "via": "owner",
            }
            with patch.object(walkthrough, "_source_edges_for_step", return_value=[edge]),                  patch.object(walkthrough, "_source_dependency_address", return_value=(owner, "owner")),                  patch.object(walkthrough, "_runtime_code", return_value="0x"),                  patch.object(walkthrough, "_read_contract_getter", return_value=(True, owner)):
                origin, diagnostics = walkthrough._probe_source_guards(
                    root,
                    "http://127.0.0.1:8545",
                    step,
                    model,
                    [model],
                    "0x" + "2" * 40,
                )

        self.assertIsNotNone(origin)
        self.assertTrue(any("is an EOA (wallet address)" in line for line in diagnostics))
        self.assertFalse(any(str(line).startswith("LAB ISSUE:") for line in diagnostics))


    def test_replay_assessment_falls_back_to_text_trace_when_structured_trace_is_missing(self):
        story = walkthrough.WalkthroughStory(
            story_id="RP-TEXT",
            title="Replay probe",
            goal="repeat payout",
            actions=[{"function": "release()"}, {"function": "release()"}],
            execution_scope="persistent_story",
            reset_between_actions=False,
        )
        actor = walkthrough.Actor("Attacker", "0x" + "1" * 40, 2)
        target = "0x" + "2" * 40
        setup = walkthrough.Step(
            1, actor.name, "Escrow", target, "createescrow(uint256,address)",
            [1, actor.address], value_wei=1, status="success",
        )
        first = walkthrough.Step(
            2, actor.name, "Escrow", target, "release()", [], status="success",
        )
        second = walkthrough.Step(
            3, actor.name, "Escrow", target, "release()", [], status="success",
        )
        key = actor.address.lower()
        second.balance_before = {key: 10**18}
        second.balance_after = {key: 10**18 - 200000}
        second.execution_edges = []
        second.trace_edges = [f"CALL to={actor.address} value=1 wei"]

        walkthrough_finding_patterns.assess_replay_story(
            story, [setup, first, second], [actor]
        )

        self.assertEqual(story.signal, "CONFIRMED")
        self.assertIn("1 wei", " ".join(story.evidence))
    def test_walkthrough_security_lens_uses_shared_pattern_signal(self):
        step = walkthrough.Step(
            1,
            "Alice",
            "Fallback",
            "0x" + "3" * 40,
            "withdraw()",
            [],
            status="success",
        )
        step.security_signals = [{
            "pattern_id": "REPLAY-001",
            "verification_status": "REVIEW",
            "description": "payout path needs state-consumption review",
            "next": "Compare the entitlement before and after the repeated call.",
        }]
        model = walkthrough.ContractModel(
            name="Fallback",
            source="src/Fallback.sol",
            artifact="out/Fallback.sol/Fallback.json",
            function_locations={"withdraw": 30},
        )
        rendered = walkthrough._render_interaction_graph_full(
            pathlib.Path("/tmp/project"),
            step,
            [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)],
            model,
            [model],
            False,
        )
        self.assertIn("SECURITY LENS", rendered)
        self.assertIn("REPLAY-001 [REVIEW]", rendered)
        self.assertIn("payout path needs state-consumption review", rendered)

    def test_isolated_probe_scope_is_explicit(self):
        step = walkthrough.Step(
            1,
            "Alice",
            "Demo",
            "0x" + "2" * 40,
            "release()",
            [],
            observation_scope="isolated_probe",
        )
        self.assertEqual(step.observation_scope, "isolated_probe")
        self.assertNotEqual(step.observation_scope, "persistent_story")


    def test_security_radar_surfaces_project_patterns_before_function_is_observed(self):
        class Context:
            def security_patterns(self, _root, **kwargs):
                return [{
                    "pattern_id": "REPLAY-001",
                    "title": "Replayable payout / claim path",
                    "contract": "Fallback",
                    "function": "withdraw()",
                    "verification_status": "REVIEW",
                    "description": "Repeated payout needs state-consumption review.",
                    "next": "Compare the first and second payout state delta.",
                }]
        class Host:
            audit_context = Context()

        # The radar reads the same shared context used by the per-step SECURITY LENS.
        with patch.dict(sys.modules, {"audit_context": Context()}, clear=False):
            rendered = walkthrough._render_security_radar(
                pathlib.Path("/tmp/project"),
                walkthrough.ContractModel(
                    name="Fallback", source="src/Fallback.sol", artifact="out/Fallback.sol/Fallback.json"
                ),
                False,
            )
        self.assertIn("SECURITY RADAR", rendered)
        self.assertIn("REPLAY-001", rendered)
        self.assertIn("REVIEW", rendered)


    def test_storage_renderer_is_human_first_for_mapping_rows_and_hides_evm_hash_by_default(self):
        storage = [{
            "label": "contributions",
            "slot": "0",
            "type": "mapping(address => uint256)",
            "encoding": "mapping",
            "mapping": {
                "key_type": "address",
                "value_type": "uint256",
                "native_value": True,
                "rows": [{
                    "key": "0x" + "1" * 40,
                    "value": 1000000000000000000,
                    "slot": "0x" + "2" * 64,
                }],
            },
        }]
        actors = [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)]
        rendered = walkthrough._render_storage(storage, False, actors)
        self.assertIn("keeps track of how much ETH each address has contributed", rendered)
        self.assertIn("find a key (like Alice), then read the value stored for that key", rendered)
        self.assertIn("slot 0", rendered)
        self.assertIn("Alice → 1 ETH", rendered)
        self.assertNotIn("1,000,000,000,000,000,000 wei", rendered)
        self.assertNotIn("keccak256(pad(key)", rendered)
        self.assertNotIn("0x" + "2" * 64, rendered)

    def test_storage_renderer_exposes_mapping_slot_math_only_in_technical_mode(self):
        slot = "0x" + "2" * 64
        storage = [{
            "label": "contributions",
            "slot": "0",
            "type": "mapping(address => uint256)",
            "encoding": "mapping",
            "mapping": {
                "key_type": "address",
                "value_type": "uint256",
                "rows": [{
                    "key": "0x" + "1" * 40,
                    "value": 1,
                    "slot": slot,
                }],
            },
        }]
        actors = [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)]
        rendered = walkthrough._render_storage(storage, False, actors, technical=True)
        self.assertIn("technical storage:", rendered)
        self.assertIn("row location        = keccak256(pad(key) || pad(0))", rendered)
        self.assertIn(slot, rendered)
        self.assertIn("Alice → 1 [uint256]", rendered)

    def test_storage_renderer_explains_plain_slot_as_numbered_storage_box(self):
        storage = [{
            "label": "owner",
            "slot": "1",
            "type": "address",
            "encoding": "inplace",
            "value": "0x" + "1" * 40,
            "raw": "0x" + "0" * 24 + "1" * 40,
        }]
        actors = [walkthrough.Actor("Alice", "0x" + "1" * 40, 0)]
        rendered = walkthrough._render_storage(storage, False, actors)
        self.assertIn("remembers the current owner", rendered)
        self.assertIn("Alice", rendered)
        self.assertIn("slot 1", rendered)
        self.assertIn("numbered storage box", rendered)
        self.assertNotIn("raw word", rendered)


if __name__ == "__main__":
    unittest.main()
