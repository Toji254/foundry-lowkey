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

    def test_default_inventory_explains_payable_and_native_eth_outflow(self):
        code, output = self._run([])
        self.assertEqual(code, 0)
        self.assertIn(
            "deposit()  [PAYABLE • CAN RECEIVE ETH • attach with --eth <amount>]",
            output,
        )
        self.assertIn(
            "withdraw(uint256)  [NONPAYABLE • SENDS ETH (source-detected)]",
            output,
        )
        self.assertIn("setTreasury(address)  [NONPAYABLE]", output)
        self.assertIn("ETH FLOW NOTES:", output)
        self.assertIn("attach ETH separately from the function arguments", output)
        self.assertIn("lk send <function> [args...] --eth 2", output)
        self.assertIn("proxy/delegatecall, dynamic and other indirect paths may need review", output)

    def test_default_inventory_shows_outflow_destination_and_amount(self):
        code, output = self._run([])
        self.assertEqual(code, 0)
        self.assertIn(
            "ETH OUT 1: call{value} | to: msg.sender | amount: amount",
            output,
        )
        self.assertIn("ETH ENTRYPOINTS:", output)
        self.assertIn("receive()  [PAYABLE • CAN RECEIVE ETH", output)
        self.assertIn("fallback()  [NONPAYABLE • cannot receive attached ETH]", output)
        self.assertIn(
            "ETH OUT 1: call{value} | to: payable(treasury) | amount: msg.value",
            output,
        )

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
        self.assertEqual(code, 0)
        self.assertIn("ETH ENTRYPOINTS:", output.getvalue())
        self.assertIn("receive()  [PAYABLE • CAN RECEIVE ETH", output.getvalue())

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


if __name__ == "__main__":
    unittest.main()
