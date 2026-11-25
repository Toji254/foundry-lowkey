import contextlib
import importlib.util
import io
import json
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "lk.py"
spec = importlib.util.spec_from_file_location("lowkeycast_function_inventory", MODULE)
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


class FunctionInventoryTests(unittest.TestCase):
    def _fixture(self):
        tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(tmp.name)
        (root / "src").mkdir()
        (root / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
        source = root / "src" / "Foo.sol"
        source.write_text(
            """
            contract Foo {
                mapping(address => uint256) public balances;
                address public treasury;

                modifier onlyOwner() { _; }
                modifier nonReentrant() { _; }

                event Deposit(address indexed who, uint256 amount);
                event Withdraw(address indexed who, uint256 amount);

                function deposit() external payable {
                    balances[msg.sender] += msg.value;
                    emit Deposit(msg.sender, msg.value);
                }

                function withdraw(uint256 amount) public nonReentrant {
                    balances[msg.sender] -= amount;
                    (bool ok, ) = msg.sender.call{value: amount}("");
                    require(ok);
                    emit Withdraw(msg.sender, amount);
                }

                function setTreasury(address next) external onlyOwner {
                    treasury = next;
                }

                function balanceOf(address who) external view returns (uint256) {
                    return balances[who];
                }

                receive() external payable {
                    (bool ok, ) = payable(treasury).call{value: msg.value}("");
                    require(ok);
                }

                fallback() external {}
            }
            """,
            encoding="utf-8",
        )
        artifact = {
            "contractName": "Foo",
            "sourceName": "src/Foo.sol",
            "abi": [
                {"type": "function", "name": "deposit", "inputs": [], "outputs": [], "stateMutability": "payable"},
                {"type": "function", "name": "withdraw", "inputs": [{"name": "amount", "type": "uint256"}], "outputs": [], "stateMutability": "nonpayable"},
                {"type": "function", "name": "setTreasury", "inputs": [{"name": "next", "type": "address"}], "outputs": [], "stateMutability": "nonpayable"},
                {"type": "function", "name": "balanceOf", "inputs": [{"name": "who", "type": "address"}], "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"},
                {"type": "function", "name": "balances", "inputs": [{"name": "", "type": "address"}], "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"},
                {"type": "receive", "stateMutability": "payable"},
                {"type": "fallback", "stateMutability": "nonpayable"},
            ],
            "storageLayout": {"storage": [
                {"label": "balances", "slot": "0", "type": "t_mapping(t_address,t_uint256)"},
                {"label": "treasury", "slot": "1", "type": "t_address"},
            ]},
            "methodIdentifiers": {
                "deposit()": "0xd0e30db0",
                "withdraw(uint256)": "0x2e1a7d4d",
                "setTreasury(address)": "0x1c5f8b1d",
                "balanceOf(address)": "0x70a08231",
                "balances(address)": "0x27e235e3",
            },
        }
        artifact_path = root / "out" / "Foo.sol" / "Foo.json"
        artifact_path.parent.mkdir(parents=True)
        artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
        config = {
            "target": "0x" + "1" * 40,
            "target_contract": "Foo",
            "abi_paths": {"0x" + "1" * 40: str(artifact_path)},
            "project_roots": {"0x" + "1" * 40: str(root)},
            "aliases": {}, "targets": {}, "rpc": None,
        }
        return tmp, root, config

    def _run(self, args):
        tmp, root, config = self._fixture()
        old = os.getcwd()
        output = io.StringIO()
        try:
            os.chdir(root)
            with patch.object(lk, "cast_output", return_value=(1, "", "")), contextlib.redirect_stdout(output):
                code = lk.run_functions(config, args)
        finally:
            os.chdir(old)
            tmp.cleanup()
        return code, output.getvalue()

    def test_source_resolution_uses_selected_contract_when_artifact_metadata_is_missing(self):
        tmp, root, config = self._fixture()
        old = os.getcwd()
        output = io.StringIO()
        try:
            artifact_path = pathlib.Path(config["abi_paths"][config["target"]])
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
            artifact.pop("contractName", None)
            artifact.pop("sourceName", None)
            artifact_path.write_text(json.dumps(artifact), encoding="utf-8")

            os.chdir(root)
            with patch.object(lk, "cast_output", return_value=(1, "", "")), contextlib.redirect_stdout(output):
                code = lk.run_functions(config, ["--verbose"])
        finally:
            os.chdir(old)
            tmp.cleanup()

        rendered = output.getvalue()
        self.assertEqual(code, 0)
        self.assertIn(f"Source   : {root / 'src' / 'Foo.sol'}", rendered)
        self.assertIn("withdraw(uint256)", rendered)
        self.assertIn("ether      : SENDS", rendered)
        self.assertIn("ETH OUT 1: call{value} | to: msg.sender | amount: amount", rendered)

    def test_verbose_inventory_shows_audit_metadata(self):
        code, output = self._run(["-v"])
        self.assertEqual(code, 0)
        self.assertIn("LOWKEY // FUNCTION INVENTORY • VERBOSE", output)
        self.assertIn("withdraw(uint256)", output)
        self.assertIn("visibility : public", output)
        self.assertIn("modifiers  : nonReentrant", output)
        self.assertIn("writes     : balances", output)
        self.assertIn("calls      : call", output)
        self.assertIn("ether      : SENDS", output)
        self.assertIn("risk flags : STATE-WRITE", output)
        self.assertIn("selector   : 0x2e1a7d4d", output)

    def test_default_inventory_is_a_compact_dashboard(self):
        code, output = self._run([])
        self.assertEqual(code, 0)
        self.assertIn("LOWKEY  /  FUNCTION INVENTORY", output)
        self.assertIn("CONTRACT  Foo", output)
        self.assertIn("SUMMARY   5 functions · 3 write · 1 read · 1 getters", output)
        self.assertIn("WRITE FUNCTIONS: 3", output)
        self.assertIn("READ FUNCTIONS: 1", output)
        self.assertIn("STORAGE GETTERS: 1", output)
        self.assertIn("deposit()", output)
        self.assertIn("PAYABLE", output)
        self.assertIn("↑ RECEIVES ETH", output)
        self.assertIn("withdraw(uint256)", output)
        self.assertIn("↓ SENDS ETH", output)
        self.assertIn("use --eth <amount>", output)
        self.assertIn("ETH FLOW", output)
        self.assertIn("indirect flows need review", output)
        function_section = output.split("ETH FLOW", 1)[0]
        self.assertNotIn("! UNASSESSED", function_section)
        self.assertIn("! UNASSESSED", output)
        self.assertNotIn(chr(27), output)

    def test_default_inventory_shows_outflow_destination_and_amount_separately(self):
        code, output = self._run([])
        self.assertEqual(code, 0)
        self.assertIn("ETH OUT 1", output)
        self.assertIn("via       call{value}", output)
        self.assertIn("recipient msg.sender", output)
        self.assertIn("amount    amount", output)
        self.assertIn("ETH ENTRYPOINTS (2)", output)
        self.assertIn("receive()", output)
        self.assertIn("fallback()", output)
        self.assertIn("recipient payable(treasury)", output)
        self.assertIn("amount    msg.value", output)

    def test_generated_public_getter_is_not_marked_source_unavailable(self):
        code, output = self._run([])
        self.assertEqual(code, 0)
        getter_tail = output.split("STORAGE GETTERS: 1", 1)[1]
        getter_section = getter_tail.split("ETH ENTRYPOINTS", 1)[0].split("ETH FLOW", 1)[0]
        self.assertIn("balances(address)", getter_section)
        self.assertIn("[public storage getter]", getter_section)
        self.assertNotIn("NOT ASSESSED", getter_section)

    def test_inventory_supports_contracts_with_only_receive_or_fallback(self):
        tmp, root, config = self._fixture()
        old = os.getcwd()
        output = io.StringIO()
        try:
            artifact_path = pathlib.Path(config["abi_paths"][config["target"]])
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
            artifact["abi"] = [
                {"type": "receive", "stateMutability": "payable"},
            ]
            artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
            os.chdir(root)
            with patch.object(lk, "cast_output", return_value=(1, "", "")), contextlib.redirect_stdout(output):
                code = lk.run_functions(config, [])
        finally:
            os.chdir(old)
            tmp.cleanup()
        rendered = output.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("ETH ENTRYPOINTS (1)", rendered)
        self.assertIn("receive()", rendered)
        self.assertIn("↑ RECEIVES ETH", rendered)


    def test_multiple_native_eth_outflows_are_displayed_individually(self):
        tmp, root, config = self._fixture()
        old = os.getcwd()
        output = io.StringIO()
        try:
            source = root / "src" / "Foo.sol"
            content = source.read_text(encoding="utf-8")
            content = content.replace(
                'msg.sender.call{value: amount}("");',
                'msg.sender.call{value: amount}("");\\n'
                '                    payable(treasury).call{value: amount}("");',
            )
            source.write_text(content, encoding="utf-8")
            os.chdir(root)
            with patch.object(lk, "cast_output", return_value=(1, "", "")), contextlib.redirect_stdout(output):
                code = lk.run_functions(config, [])
        finally:
            os.chdir(old)
            tmp.cleanup()

        rendered = output.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("ETH OUT 1", rendered)
        self.assertIn("ETH OUT 2", rendered)
        self.assertIn("recipient msg.sender", rendered)
        self.assertIn("recipient payable(treasury)", rendered)

    def test_source_unavailable_is_explicit_for_write_functions_but_not_getters(self):
        tmp, root, config = self._fixture()
        old = os.getcwd()
        output = io.StringIO()
        try:
            (root / "src" / "Foo.sol").unlink()
            os.chdir(root)
            with patch.object(lk, "cast_output", return_value=(1, "", "")), contextlib.redirect_stdout(output):
                code = lk.run_functions(config, [])
        finally:
            os.chdir(old)
            tmp.cleanup()

        rendered = output.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("PAYABLE · ↑ RECEIVES ETH · ! UNASSESSED", rendered)
        self.assertIn("NONPAYABLE · ! UNASSESSED", rendered)
        getter_tail = rendered.split("STORAGE GETTERS: 1", 1)[1]
        getter_section = getter_tail.split("ETH ENTRYPOINTS", 1)[0].split("ETH FLOW", 1)[0]
        self.assertIn("balances(address)", getter_section)
        self.assertNotIn("UNASSESSED", getter_section)

    def test_contract_with_only_public_getters_has_clean_inventory(self):
        tmp, root, config = self._fixture()
        old = os.getcwd()
        output = io.StringIO()
        try:
            artifact_path = pathlib.Path(config["abi_paths"][config["target"]])
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
            artifact["abi"] = [
                {
                    "type": "function",
                    "name": "balances",
                    "inputs": [{"name": "", "type": "address"}],
                    "outputs": [{"name": "", "type": "uint256"}],
                    "stateMutability": "view",
                },
            ]
            artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
            os.chdir(root)
            with patch.object(lk, "cast_output", return_value=(1, "", "")), contextlib.redirect_stdout(output):
                code = lk.run_functions(config, [])
        finally:
            os.chdir(old)
            tmp.cleanup()

        rendered = output.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("SUMMARY   1 functions · 0 write · 0 read · 1 getters", rendered)
        self.assertIn("STORAGE GETTERS: 1", rendered)
        self.assertIn("balances(address)", rendered)
        getter_tail = rendered.split("STORAGE GETTERS: 1", 1)[1]
        getter_section = getter_tail.split("ETH ENTRYPOINTS", 1)[0].split("ETH FLOW", 1)[0]
        self.assertNotIn("NOT ASSESSED", getter_section)

    def test_function_without_eth_outflow_is_not_labelled_as_sending_eth(self):
        tmp, root, config = self._fixture()
        old = os.getcwd()
        output = io.StringIO()
        try:
            artifact_path = pathlib.Path(config["abi_paths"][config["target"]])
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
            artifact["abi"] = [
                {
                    "type": "function",
                    "name": "setTreasury",
                    "inputs": [{"name": "next", "type": "address"}],
                    "outputs": [],
                    "stateMutability": "nonpayable",
                },
            ]
            artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
            os.chdir(root)
            with patch.object(lk, "cast_output", return_value=(1, "", "")), contextlib.redirect_stdout(output):
                code = lk.run_functions(config, [])
        finally:
            os.chdir(old)
            tmp.cleanup()

        rendered = output.getvalue()
        function_section = rendered.split("ETH FLOW", 1)[0]
        self.assertEqual(code, 0)
        self.assertIn("setTreasury(address)", function_section)
        self.assertIn("NONPAYABLE", function_section)
        self.assertNotIn("↓ SENDS ETH", function_section)
        self.assertNotIn("ETH OUT", function_section)


    def test_terminal_styling_respects_no_color_and_non_tty_output(self):
        class TTYStream(io.StringIO):
            def isatty(self):
                return True

        stream = TTYStream()
        with patch.dict(os.environ, {"NO_COLOR": "1", "TERM": "xterm"}):
            self.assertEqual(lk._function_terminal_style("heading", "title", stream), "heading")

        with patch.dict(os.environ, {"TERM": "xterm"}, clear=True):
            styled = lk._function_terminal_style("heading", "title", stream)
            self.assertTrue(styled.startswith(chr(27) + "[1m"))
            self.assertTrue(styled.endswith(chr(27) + "[0m"))

        self.assertEqual(lk._function_terminal_style("plain", "title", io.StringIO()), "plain")

    def test_wrapped_function_details_keep_the_full_expression(self):
        output = io.StringIO()
        expression = "destination expression with several parts " * 3
        with patch.object(lk.shutil, "get_terminal_size", return_value=os.terminal_size((52, 24))):
            with contextlib.redirect_stdout(output):
                lk._function_print_wrapped("        recipient ", expression)
        rendered = output.getvalue()
        expected = "        recipient " + expression + "\n"
        self.assertEqual("".join(rendered.split()), "".join(expected.split()))


    def test_native_eth_outflow_detector_covers_common_solidity_patterns(self):
        payable_source = {
            "params": "address payable recipient, uint256 amount",
            "payable_names": ["recipient"],
        }
        cases = [
            (
                'payable(recipient).call{value: amount, gas: 50000}("");',
                "payable(recipient)", "amount", "call{value}",
            ),
            (
                'payable(EscrowID[escrowId].recipient).call{value: EscrowID[escrowId].amount}("");',
                "payable(EscrowID[escrowId].recipient)",
                "EscrowID[escrowId].amount",
                "call{value}",
            ),
            (
                "recipient.transfer(amount);",
                "recipient", "amount", "transfer",
            ),
            (
                "recipient.send(amount);",
                "recipient", "amount", "send",
            ),
            (
                "new Child{value: amount}(recipient);",
                "new Child (created contract address)", "amount", "CREATE with value",
            ),
            (
                "selfdestruct(payable(recipient));",
                "payable(recipient)", "address(this).balance", "selfdestruct",
            ),
        ]
        for body, destination, amount, mechanism in cases:
            with self.subTest(body=body):
                findings = lk._extract_native_eth_outflows(body, payable_source)
                self.assertTrue(findings)
                self.assertEqual(findings[0]["destination"], destination)
                self.assertEqual(findings[0]["amount"], amount)
                self.assertEqual(findings[0]["mechanism"], mechanism)

    def test_native_eth_outflow_detector_covers_yul_call_and_create(self):
        body = """
            assembly {
                pop(call(gas(), recipient, amount, 0, 0, 0, 0))
                pop(create(amount, codeOffset, codeSize))
                pop(create2(amount, codeOffset, codeSize, salt))
            }
        """
        findings = lk._extract_native_eth_outflows(body)
        self.assertEqual(
            [(item["destination"], item["amount"], item["mechanism"]) for item in findings],
            [
                ("recipient", "amount", "assembly CALL"),
                ("new contract address (CREATE)", "amount", "assembly CREATE"),
                ("new contract address (CREATE2)", "amount", "assembly CREATE2"),
            ],
        )

    def test_native_eth_outflow_detector_does_not_mislabel_erc20_transfer(self):
        body = """
            token.transfer(recipient, amount);
            IERC20(token).transfer(recipient, amount);
        """
        self.assertEqual(lk._extract_native_eth_outflows(body), [])

    def test_native_eth_outflow_detector_follows_same_file_internal_helpers(self):
        external_function = {
            "name": "withdraw",
            "line": 10,
            "visibility": "external",
            "params": "address payable recipient, uint256 amount",
            "payable_names": ["recipient"],
            "body": "_pay(recipient, amount);",
        }
        helper = {
            "name": "_pay",
            "line": 20,
            "visibility": "private",
            "params": "address payable recipient, uint256 amount",
            "payable_names": ["recipient"],
            "body": 'recipient.call{value: amount}("");',
        }
        findings = lk._collect_native_eth_outflows(
            external_function,
            [external_function, helper],
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["destination"], "recipient")
        self.assertEqual(findings[0]["amount"], "amount")
        self.assertEqual(findings[0]["via"], "_pay()")

    def test_visibility_short_filter(self):
        code, output = self._run(["-V", "external"])
        self.assertEqual(code, 0)
        self.assertIn("deposit()", output)
        self.assertIn("setTreasury(address)", output)
        self.assertIn("balanceOf(address)", output)
        self.assertNotIn("withdraw(uint256)", output)

    def test_mutability_filter(self):
        code, output = self._run(["-m", "payable"])
        self.assertEqual(code, 0)
        self.assertIn("deposit()", output)
        self.assertNotIn("withdraw(uint256)", output)
        self.assertNotIn("balanceOf(address)", output)

    def test_class_filter(self):
        code, output = self._run(["-c", "admin"])
        self.assertEqual(code, 0)
        self.assertIn("setTreasury(address)", output)
        self.assertNotIn("deposit()", output)

    def test_risk_view(self):
        code, output = self._run(["-r"])
        self.assertEqual(code, 0)
        self.assertIn("LOWKEY // FUNCTION INVENTORY • REVIEW FLAGS", output)
        self.assertIn("withdraw(uint256)", output)
        self.assertIn("EXTERNAL-CALL", output)
        self.assertIn("VALUE-FLOW", output)

    def test_query_is_filtered_before_top_eight(self):
        code, output = self._run(["withdraw", "-V", "public"])
        self.assertEqual(code, 0)
        self.assertIn("withdraw(uint256)", output)

    def test_dispatch_passes_all_function_args(self):
        tmp, root, config = self._fixture()
        old = os.getcwd()
        output = io.StringIO()
        try:
            os.chdir(root)
            with patch.object(lk, "run_functions", return_value=0) as runner:
                code = lk.dispatch_command("fn", ["-V", "external", "-r"], config)
        finally:
            os.chdir(old)
            tmp.cleanup()
        self.assertEqual(code, 0)
        runner.assert_called_once_with(config, ["-V", "external", "-r"])


    def test_active_contract_name_query_shows_the_full_inventory(self):
        code, output = self._run(["Foo"])
        self.assertEqual(code, 0)
        self.assertIn("SUMMARY   5 functions · 3 write · 1 read · 1 getters", output)
        self.assertIn("deposit()", output)
        self.assertIn("withdraw(uint256)", output)
        self.assertIn("balanceOf(address)", output)
        self.assertNotIn("MATCH     Foo", output)
        self.assertIn("SELECTED", output)
        self.assertIn("contract selector 'Foo' -> complete ABI inventory", output)


    def test_explicit_query_is_not_reinterpreted_as_contract_selection(self):
        options, query = lk._parse_function_options(["--query", "Foo"])
        self.assertIsNotNone(options)
        self.assertTrue(options.query_explicit)
        self.assertEqual(query, "Foo")
        self.assertEqual(
            lk._function_query_for_target(query, "Foo", explicit_query=options.query_explicit),
            ("Foo", False),
        )
        self.assertEqual(
            lk._function_query_for_target("Foo", "Foo"),
            ("", True),
        )


    def test_short_query_flag_is_supported(self):
        options, query = lk._parse_function_options(["-q", "withdraw(uint256)"])
        self.assertTrue(options.query_explicit)
        self.assertEqual(query, "withdraw(uint256)")


    def test_compiler_ast_effects_exclude_lexical_edges_and_preserve_inferred_paths(self):
        function_id = "function:src/Foo.sol:Foo.withdraw(uint256)"
        helper_id = "function:src/Foo.sol:Foo._debit(address,uint256)"
        storage_id = "mapping:src/Foo.sol:Foo.balances"
        storage_edge_id = "SOLC_AST_STORAGE:WRITES:helper:balances:src/Foo.sol:22"
        index = {
            "ast": {"functions": 2, "covered_function_ids": [function_id, helper_id]},
            "nodes": [
                {"id": function_id, "kind": "function", "name": "withdraw", "qualified_name": "Foo.withdraw(uint256)"},
                {"id": helper_id, "kind": "function", "name": "_debit", "qualified_name": "Foo._debit(address,uint256)"},
                {"id": storage_id, "kind": "mapping", "name": "balances"},
            ],
            "edges": [
                {
                    "id": "SOLC_AST:CALLS:withdraw:debit",
                    "from": function_id, "to": helper_id, "kind": "CALLS",
                    "evidence": "SOLC_AST_DECLARATION_REFERENCE", "resolution": "DIRECT",
                    "source": {"file": "src/Foo.sol", "line": 12, "column": 9},
                },
                {
                    "id": storage_edge_id,
                    "from": helper_id, "to": storage_id, "kind": "WRITES",
                    "evidence": "SOLC_AST_STORAGE_DECLARATION_REFERENCE", "resolution": "DIRECT",
                    "access_path": "balances[user]", "operation": "+=", "source": {"file": "src/Foo.sol", "line": 22, "column": 9},
                },
                {
                    "id": f"INFERRED:{function_id}:{storage_edge_id}",
                    "from": function_id, "to": storage_id, "kind": "WRITES",
                    "evidence": "CALL_GRAPH_PROPAGATION", "resolution": "INFERRED",
                    "via": [function_id, helper_id], "access_path": "balances[user]", "operation": "+=",
                    "source": {"file": "src/Foo.sol", "line": 22, "column": 9},
                },
                {
                    "id": "LEXICAL:WRITES:withdraw:balances",
                    "from": function_id, "to": storage_id, "kind": "WRITES",
                    "evidence": "LEXICAL_SOURCE", "resolution": "INFERRED",
                    "access_path": "balances[user]", "source": {"file": "src/Foo.sol", "line": 12, "column": 9},
                },
            ],
        }
        status, effects = lk._compiler_ast_effects_for_function(index, {"id": function_id})
        self.assertEqual(status, "COVERED")
        self.assertEqual(len(effects), 2)
        self.assertEqual({item["ast_origin"] for item in effects}, {"DIRECT", "INFERRED"})
        self.assertTrue(all(item["evidence"] != "LEXICAL_SOURCE" for item in effects))


    def test_orderbook_effect_graph_covers_swap_creation_execution_and_increase_paths(self):
        # Normalized compiler-AST regression graph based on GMX OrderBook's
        # call/effect structure. Direct facts and propagated helper effects
        # are intentionally represented as distinct evidence.
        functions = {
            "create": "function:src/OrderBook.sol:OrderBook.createSwapOrder(address,address,uint256,uint256,uint256,bool)",
            "create_helper": "function:src/OrderBook.sol:OrderBook._createSwapOrder(address,address,uint256,uint256,uint256,bool)",
            "execute": "function:src/OrderBook.sol:OrderBook.executeSwapOrder(uint256,address payable)",
            "swap_helper": "function:src/OrderBook.sol:OrderBook._swap(address,address,uint256,uint256,address payable)",
            "increase": "function:src/OrderBook.sol:OrderBook.executeIncreaseOrder(uint256)",
        }
        storage = {
            "index": "state:src/OrderBook.sol:OrderBook.swapOrdersIndex",
            "orders": "mapping:src/OrderBook.sol:OrderBook.swapOrders",
            "increase_orders": "mapping:src/OrderBook.sol:OrderBook.increaseOrders",
        }
        external = {
            "router": "function:src/interfaces/IRouter.sol:IRouter.pluginTransfer(address,address,uint256,address)",
            "token_transfer": "function:src/interfaces/IERC20.sol:IERC20.transfer(address,uint256)",
            "swap": "function:src/interfaces/IVault.sol:IVault.swap(address,address,uint256,uint256,address)",
        }
        nodes = [
            {"id": identifier, "kind": "function", "name": identifier.rsplit(".", 1)[-1]}
            for identifier in [*functions.values(), *external.values()]
        ] + [
            {"id": identifier, "kind": "storage", "name": identifier.rsplit(".", 1)[-1]}
            for identifier in storage.values()
        ]
        edges = [
            {
                "id": "ast:create:router",
                "from": functions["create"], "to": external["router"], "kind": "EXTERNAL_CALL",
                "evidence": "SOLC_AST_DECLARATION_REFERENCE", "resolution": "DIRECT",
                "source": {"file": "src/OrderBook.sol", "line": 211, "column": 9},
            },
            {
                "id": "ast:create:helper",
                "from": functions["create"], "to": functions["create_helper"], "kind": "CALLS",
                "evidence": "SOLC_AST_DECLARATION_REFERENCE", "resolution": "DIRECT",
                "source": {"file": "src/OrderBook.sol", "line": 212, "column": 9},
            },
            {
                "id": "ast:helper:index",
                "from": functions["create_helper"], "to": storage["index"], "kind": "WRITES",
                "evidence": "SOLC_AST_STORAGE_DECLARATION_REFERENCE", "resolution": "DIRECT",
                "access_path": "swapOrdersIndex", "operation": "++",
                "source": {"file": "src/OrderBook.sol", "line": 231, "column": 9},
            },
            {
                "id": "ast:helper:orders",
                "from": functions["create_helper"], "to": storage["orders"], "kind": "WRITES",
                "evidence": "SOLC_AST_STORAGE_DECLARATION_REFERENCE", "resolution": "DIRECT",
                "access_path": "swapOrders[swapOrdersIndex]", "operation": "=",
                "source": {"file": "src/OrderBook.sol", "line": 232, "column": 9},
            },
            {
                "id": f"INFERRED:{functions['create']}:ast:helper:index",
                "from": functions["create"], "to": storage["index"], "kind": "WRITES",
                "evidence": "CALL_GRAPH_PROPAGATION", "resolution": "INFERRED",
                "via": [functions["create"], functions["create_helper"]],
                "access_path": "swapOrdersIndex", "operation": "++",
                "source": {"file": "src/OrderBook.sol", "line": 231, "column": 9},
            },
            {
                "id": f"INFERRED:{functions['create']}:ast:helper:orders",
                "from": functions["create"], "to": storage["orders"], "kind": "WRITES",
                "evidence": "CALL_GRAPH_PROPAGATION", "resolution": "INFERRED",
                "via": [functions["create"], functions["create_helper"]],
                "access_path": "swapOrders[swapOrdersIndex]", "operation": "=",
                "source": {"file": "src/OrderBook.sol", "line": 232, "column": 9},
            },
            {
                "id": "ast:execute:delete",
                "from": functions["execute"], "to": storage["orders"], "kind": "DELETES",
                "evidence": "SOLC_AST_STORAGE_DECLARATION_REFERENCE", "resolution": "DIRECT",
                "access_path": "swapOrders[orderIndex]", "operation": "delete",
                "source": {"file": "src/OrderBook.sol", "line": 301, "column": 9},
            },
            {
                "id": "ast:execute:swap",
                "from": functions["execute"], "to": functions["swap_helper"], "kind": "CALLS",
                "evidence": "SOLC_AST_DECLARATION_REFERENCE", "resolution": "DIRECT",
                "source": {"file": "src/OrderBook.sol", "line": 309, "column": 9},
            },
            {
                "id": "ast:swap:vault",
                "from": functions["swap_helper"], "to": external["swap"], "kind": "EXTERNAL_CALL",
                "evidence": "SOLC_AST_DECLARATION_REFERENCE", "resolution": "DIRECT",
                "source": {"file": "src/OrderBook.sol", "line": 355, "column": 9},
            },
            {
                "id": "ast:swap:token",
                "from": functions["swap_helper"], "to": external["token_transfer"], "kind": "EXTERNAL_CALL",
                "evidence": "SOLC_AST_DECLARATION_REFERENCE", "resolution": "DIRECT",
                "source": {"file": "src/OrderBook.sol", "line": 361, "column": 9},
            },
            {
                "id": f"INFERRED:{functions['execute']}:ast:swap:vault",
                "from": functions["execute"], "to": external["swap"], "kind": "EXTERNAL_CALL",
                "evidence": "CALL_GRAPH_PROPAGATION", "resolution": "INFERRED",
                "via": [functions["execute"], functions["swap_helper"]],
                "source": {"file": "src/OrderBook.sol", "line": 355, "column": 9},
            },
            {
                "id": f"INFERRED:{functions['execute']}:ast:swap:token",
                "from": functions["execute"], "to": external["token_transfer"], "kind": "EXTERNAL_CALL",
                "evidence": "CALL_GRAPH_PROPAGATION", "resolution": "INFERRED",
                "via": [functions["execute"], functions["swap_helper"]],
                "source": {"file": "src/OrderBook.sol", "line": 361, "column": 9},
            },
            {
                "id": "ast:increase:delete",
                "from": functions["increase"], "to": storage["increase_orders"], "kind": "DELETES",
                "evidence": "SOLC_AST_STORAGE_DECLARATION_REFERENCE", "resolution": "DIRECT",
                "access_path": "increaseOrders[orderIndex]", "operation": "delete",
                "source": {"file": "src/OrderBook.sol", "line": 401, "column": 9},
            },
            {
                "id": "ast:increase:router",
                "from": functions["increase"], "to": external["router"], "kind": "EXTERNAL_CALL",
                "evidence": "SOLC_AST_DECLARATION_REFERENCE", "resolution": "DIRECT",
                "source": {"file": "src/OrderBook.sol", "line": 407, "column": 9},
            },
            {
                "id": "ast:increase:token",
                "from": functions["increase"], "to": external["token_transfer"], "kind": "EXTERNAL_CALL",
                "evidence": "SOLC_AST_DECLARATION_REFERENCE", "resolution": "DIRECT",
                "source": {"file": "src/OrderBook.sol", "line": 412, "column": 9},
            },
        ]
        index = {
            "ast": {"functions": len(functions), "covered_function_ids": list(functions.values())},
            "nodes": nodes,
            "edges": edges,
        }

        status, create_effects = lk._compiler_ast_effects_for_function(
            index, {"id": functions["create"]}
        )
        self.assertEqual(status, "COVERED")
        create_facts = {
            (item["kind"], item["to"], item["ast_origin"])
            for item in create_effects
        }
        self.assertIn(("EXTERNAL_CALL", external["router"], "DIRECT"), create_facts)
        self.assertIn(("WRITES", storage["index"], "INFERRED"), create_facts)
        self.assertIn(("WRITES", storage["orders"], "INFERRED"), create_facts)
        for item in create_effects:
            self.assertIn(item.get("source", {}).get("line"), {211, 212, 231, 232})
            self.assertTrue(item.get("source", {}).get("file", "").endswith("OrderBook.sol"))

        status, helper_effects = lk._compiler_ast_effects_for_function(
            index, {"id": functions["create_helper"]}
        )
        self.assertEqual(status, "COVERED")
        helper_facts = {(item["kind"], item["to"]) for item in helper_effects}
        self.assertIn(("WRITES", storage["index"]), helper_facts)
        self.assertIn(("WRITES", storage["orders"]), helper_facts)

        status, execute_effects = lk._compiler_ast_effects_for_function(
            index, {"id": functions["execute"]}
        )
        self.assertEqual(status, "COVERED")
        execute_facts = {
            (item["kind"], item["to"], item["ast_origin"])
            for item in execute_effects
        }
        self.assertIn(("DELETES", storage["orders"], "DIRECT"), execute_facts)
        self.assertIn(("EXTERNAL_CALL", external["swap"], "INFERRED"), execute_facts)
        self.assertIn(("EXTERNAL_CALL", external["token_transfer"], "INFERRED"), execute_facts)

        status, increase_effects = lk._compiler_ast_effects_for_function(
            index, {"id": functions["increase"]}
        )
        self.assertEqual(status, "COVERED")
        increase_facts = {(item["kind"], item["to"]) for item in increase_effects}
        self.assertIn(("DELETES", storage["increase_orders"]), increase_facts)
        self.assertIn(("EXTERNAL_CALL", external["router"]), increase_facts)
        self.assertIn(("EXTERNAL_CALL", external["token_transfer"]), increase_facts)

        self.assertEqual(
            lk._compiler_ast_effects_for_function(index, {"id": "uncovered-function"}),
            ("NOT_COVERED", []),
        )


    def test_verbose_function_graph_reports_typed_external_and_unresolved_calls(self):
        entry = "function:src/OrderBook.sol:OrderBook.executeSwapOrder(uint256)"
        helper = "function:src/OrderBook.sol:OrderBook._swap(address,address,uint256)"
        interface_method = "function:src/interfaces/IVault.sol:IVault.swap(address,address,uint256)"
        index = {
            "ast": {"functions": 1, "covered_function_ids": []},
            "effect_propagation": {"max_depth": 8},
            "nodes": [
                {"id": entry, "kind": "function", "qualified_name": "OrderBook.executeSwapOrder(uint256)"},
                {"id": helper, "kind": "function", "qualified_name": "OrderBook._swap(address,address,uint256)"},
                {"id": interface_method, "kind": "function", "qualified_name": "IVault.swap(address,address,uint256)"},
            ],
            "edges": [
                {
                    "id": "resolved-helper-call", "from": entry, "to": helper,
                    "kind": "CALLS", "resolution": "DIRECT", "evidence": "LEXICAL_SOURCE",
                    "source": {"file": "src/OrderBook.sol", "line": 300, "column": 9},
                },
                {
                    "id": "typed-interface-call", "from": helper, "to": interface_method,
                    "kind": "EXTERNAL_CALL", "resolution": "DIRECT",
                    "implementation_resolution": "UNRESOLVED",
                    "evidence": "LEXICAL_SOURCE", "receiver": "vault", "method": "swap",
                    "detail": "The declared interface method is identified; runtime implementation is not.",
                    "source": {"file": "src/OrderBook.sol", "line": 355, "column": 9},
                },
                {
                    "id": "dynamic-function-pointer", "from": helper,
                    "to": "function-pointer:OrderBook.executeCallback", "kind": "CALLS",
                    "resolution": "UNRESOLVED", "evidence": "LEXICAL_SOURCE",
                    "call_kind": "dynamic-function-pointer",
                    "detail": "Function pointer target depends on runtime assignment or dispatch.",
                    "source": {"file": "src/OrderBook.sol", "line": 360, "column": 9},
                },
                {
                    "id": "unknown-low-level-call", "from": helper,
                    "to": "low-level:delegatecall", "kind": "EXTERNAL_CALL",
                    "resolution": "UNRESOLVED", "evidence": "LEXICAL_SOURCE",
                    "operation": "delegatecall",
                    "source": {"file": "src/OrderBook.sol", "line": 365, "column": 9},
                },
            ],
        }

        result = lk._function_graph_boundary_edges(index, {"id": entry})
        self.assertEqual(len(result["edges"]), 3)
        self.assertEqual(len(result["unresolved"]), 3)
        self.assertFalse(result["truncated"])
        kinds = {(edge["kind"], edge.get("method"), edge.get("call_kind")) for edge in result["edges"]}
        self.assertIn(("EXTERNAL_CALL", "swap", None), kinds)
        self.assertIn(("CALLS", None, "dynamic-function-pointer"), kinds)
        self.assertIn(("EXTERNAL_CALL", None, None), kinds)

        output = io.StringIO()
        with patch.object(lk.source_index, "build_source_index", return_value=index), \
             patch.object(lk, "_function_graph_node", return_value={"id": entry}), \
             contextlib.redirect_stdout(output):
            lk._print_compiler_ast_effects(
                pathlib.Path("/tmp/orderbook"), "OrderBook", "src/OrderBook.sol",
                [{"signature": "executeSwapOrder(uint256)"}],
            )
        rendered = output.getvalue()
        self.assertIn("CALL / EXTERNAL / UNRESOLVED BOUNDARIES", rendered)
        self.assertIn("IVault.swap(address,address,uint256)", rendered)
        self.assertIn("runtime implementation UNRESOLVED", rendered)
        self.assertIn("function-pointer", rendered)
        self.assertIn("low-level:delegatecall", rendered)
        self.assertIn("ANALYSIS STATUS: PARTIALLY ANALYSED", rendered)
        self.assertIn("Do not interpret missing effects as proof", rendered)


    def test_cli_help_documents_contract_selector_and_explicit_query(self):
        for command in ("functions", "fn"):
            with self.subTest(command=command):
                output = []
                with patch.object(
                    lk, "print",
                    side_effect=lambda *args: output.append(" ".join(map(str, args))),
                    create=True,
                ):
                    code = lk._render_command_help([command])
                self.assertEqual(code, 0)
                rendered = "\\n".join(output)
                self.assertIn("-q / --query", rendered)
                self.assertIn("--query OrderBook", rendered)
                self.assertIn("complete ABI inventory", rendered)
                self.assertIn("active contract name", rendered)


if __name__ == "__main__":
    unittest.main()
