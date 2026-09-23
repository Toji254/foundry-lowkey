            self.assertEqual(result, 0)
            cast_output.assert_called_once_with([
                "cast", "decode-event", "--sig",
                "Transfer(address,address,uint256)", "0x01"
            ])

    def test_event_failure_returns_nonzero(self):
        with patch.object(lk, "cast_output", return_value=(1, "", "decode failed")):
            self.assertEqual(lk.run_event({}, ["Transfer(address,address,uint256)", "0xdeadbeef"]), 1)

    def test_cli_successful_event(self):
        with patch.object(lk, "cast_output", return_value=(0, "42", "")):
            result = self.run_cli(
                "event",
                "Ping(uint256)",
                "0x000000000000000000000000000000000000000000000000000000000000002a",
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("42", result.stdout)

    def test_indexed_event_decoding_uses_abi_topics(self):
        event = {
            "type": "event",
            "name": "Transfer",
            "inputs": [
                {"name": "from", "type": "address", "indexed": True},
                {"name": "to", "type": "address", "indexed": True},
                {"name": "amount", "type": "uint256", "indexed": False},
            ],
        }
        topic0 = "0x" + "a" * 64
        topics = [topic0, "0x" + "0" * 24 + "1" * 40, "0x" + "0" * 24 + "2" * 40]

        def cast_result(args, input_text=None):
            if args[1] == "sig-event":
                return 0, topic0, ""
            return 0, "42", ""

        with tempfile.TemporaryDirectory() as tmp:
            abi_path = pathlib.Path(tmp) / "abi.json"
            abi_path.write_text(json.dumps({"abi": [event]}), encoding="utf-8")
            output = io.StringIO()
            with patch.object(lk, "cast_output", side_effect=cast_result):
                with redirect_stdout(output):
                    result = lk.run_event(
                        {"target": "target", "abi_paths": {"target": str(abi_path)}},
                        ["Transfer(address,address,uint256)", "0x" , *topics],
                    )
        self.assertEqual(result, 0)
        self.assertIn("Indexed from", output.getvalue())
        self.assertIn("Data: 42", output.getvalue())

    def test_anvil_detection(self):
        address = "0x" + "1" * 40
        with patch.object(lk, "local_port_open", return_value=True):
            with patch.object(
                lk,
                "rpc_json",
                side_effect=["anvil/v1.8.1", [address]],
            ):
                info = lk.detect_anvil_rpc(None)
        self.assertEqual(info["url"], "http://127.0.0.1:8545")
        self.assertEqual(info["accounts"], [address])

    def test_default_anvil_actor_selection_and_unique_assignment(self):
        address = "0x" + "1" * 40
        config = {"wallets": {}, "actor": None}
        info = {"url": "http://127.0.0.1:8545", "accounts": [address]}
        with patch.object(lk, "detect_anvil_rpc", return_value=info), \
             patch.object(lk, "derive_default_anvil_key", return_value="0x" + "a" * 64), \
             patch.object(lk, "cast_output", return_value=(0, address, "")), \
             patch.object(lk, "save_config"):
            self.assertEqual(lk.select_anvil_actor(config, 0, "Alice"), 0)
            self.assertEqual(config["actor"], "Alice")
            self.assertEqual(config["wallets"]["Alice"]["anvil_index"], 0)
            self.assertEqual(lk.select_anvil_actor(config, 0, "Bob"), 2)

    def test_anvil_actor_key_is_not_stored(self):
        address = "0x" + "1" * 40
        config = {"wallets": {"Alice": {"source": "anvil-default", "anvil_index": 0}}, "actor": "Alice"}
        with patch.object(lk, "derive_default_anvil_key", return_value="0x" + "b" * 64):
            self.assertEqual(lk.resolve_wallet_key(config), "0x" + "b" * 64)
        self.assertNotIn("private_key", config["wallets"]["Alice"])

    def test_load_abi_auto_from_local_artifact(self):
        artifact = {
            "contractName": "Escrow",
            "abi": [{"type": "function", "name": "release", "inputs": [], "stateMutability": "nonpayable"}],
            "storageLayout": {"storage": []},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "Escrow.json"
            path.write_text(json.dumps(artifact), encoding="utf-8")
            with patch.object(lk, "local_artifact_paths", return_value=[str(path)]):
                config = {"target_contract": "Escrow", "abi_paths": {}}
                abi = lk.load_abi("0x" + "1" * 40, config)
        self.assertEqual(abi[0]["name"], "release")
        self.assertEqual(config["abi_paths"]["0x" + "1" * 40], str(path))

    def test_functions_separate_storage_getters(self):
        artifact = {
            "contractName": "Escrow",
            "abi": [
                {"type": "function", "name": "release", "inputs": [], "stateMutability": "nonpayable"},
                {"type": "function", "name": "balances", "inputs": [{"type": "address"}], "stateMutability": "view"},
                {"type": "function", "name": "escrow", "inputs": [{"type": "uint256"}], "stateMutability": "view"},
            ],
            "storageLayout": {
                "storage": [
                    {"label": "balances", "slot": "0", "type": "t_mapping(t_address,t_uint256)"},
                    {"label": "escrow", "slot": "1", "type": "t_mapping(t_uint256,t_struct(Create))"},
                ]
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "Escrow.json"
            path.write_text(json.dumps(artifact), encoding="utf-8")
            config = {"target": "0x" + "1" * 40, "target_contract": "Escrow", "abi_paths": { "0x" + "1" * 40: str(path) }}
            output = io.StringIO()
            with redirect_stdout(output):
                lk.run_functions(config)
        rendered = output.getvalue()
        self.assertIn("WRITE FUNCTIONS:", rendered)
        self.assertIn("STORAGE GETTERS:", rendered)
        self.assertNotIn("balances(address)", rendered.split("WRITE FUNCTIONS:", 1)[1].split("STORAGE GETTERS:", 1)[0])

    def test_deps_default_project_shows_project_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "script").mkdir()
            (root / "src" / "Escrow.sol").write_text("contract Escrow {}", encoding="utf-8")
            (root / "script" / "Deploy.s.sol").write_text(
                'import "forge-std/Script.sol";\nimport "../src/Escrow.sol";\ncontract Deploy {}',
                encoding="utf-8",
            )
            old = os.getcwd()
            try:
                os.chdir(root)
                output = io.StringIO()
                with redirect_stdout(output):
                    lk.run_deps([])
            finally:
                os.chdir(old)
        self.assertIn("script/Deploy.s.sol -> imports forge-std/Script.sol", output.getvalue())
        self.assertIn("script/Deploy.s.sol -> imports ../src/Escrow.sol", output.getvalue())

    def test_help_long_alias(self):
        result = self.run_cli("--h")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Lowkey", result.stdout)
        self.assertIn("lk actor 0 Alice", result.stdout)

    def test_cli_failure_exit_codes(self):
        cases = [
            ("event", "Transfer(address,address,uint256)", "0xdeadbeef", "0x1"),
            ("target", "not-an-address"),
            ("receipt", "not-a-hash"),
            ("scan", "/path/does/not/exist"),
            ("definitely-not-a-command",),
            ("raw", "definitely-not-a-cast-command"),
            ("receipt", "0x" + "0" * 64),
        ]
        for args in cases:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_scan_regression_markers(self):
        source = """
        contract Regression {
            function f(address target) external payable {
                target.call{value: 1 ether}(\"\");
                target.delegatecall(\"\");
                address caller = tx.origin;
            }
        }
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "Regression.sol"
            path.write_text(source, encoding="utf-8")
            result = self.run_cli("scan", tmp)
            single_file_result = self.run_cli("scan", str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(single_file_result.returncode, 0, single_file_result.stderr)
        self.assertIn("REENTRANCY REVIEW", result.stdout)
        self.assertIn("DELEGATECALL", result.stdout)
        self.assertIn("TX.ORIGIN", result.stdout)
        self.assertIn("REENTRANCY REVIEW", single_file_result.stdout)
        self.assertIn("DELEGATECALL", single_file_result.stdout)
        self.assertIn("TX.ORIGIN", single_file_result.stdout)

    def test_doctor_reports_missing_dependencies(self):
        with patch.object(lk.shutil, "which", return_value=None):
            self.assertEqual(lk.run_doctor(), 1)

    def test_solidity_identifier(self):
        self.assertEqual(
            lk.solidity_identifier("unauthorized release #1"),
            "unauthorized_release__1",
        )

if __name__ == "__main__":
    unittest.main()