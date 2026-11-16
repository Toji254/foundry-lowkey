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
spec = importlib.util.spec_from_file_location("lowkeycast_state_variable_reads", MODULE)
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


class StateVariableReadTests(unittest.TestCase):
    def _fixture(self):
        tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(tmp.name)
        (root / "src").mkdir()
        (root / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
        source = root / "src" / "Foo.sol"
        source.write_text(
            """
            contract Foo {
                uint256 public visible;
                uint256 lastHash;
                uint256 private secret;
                bool internal paused;
                mapping(address => uint256) private credits;
                uint256 public constant LIMIT = 10;
                uint256 private immutable FACTOR = 2;
                struct Position { uint256 amount; }
                Position private position;
                modifier onlyOwner() { _; }
                function writeSecret(uint256 next) external onlyOwner { secret = next; }
            }
            """,
            encoding="utf-8",
        )
        target = "0x" + "1" * 40
        artifact = {
            "contractName": "Foo",
            "sourceName": "src/Foo.sol",
            "abi": [
                {"type": "function", "name": "visible", "inputs": [], "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"},
                {"type": "function", "name": "writeSecret", "inputs": [{"name": "next", "type": "uint256"}], "outputs": [], "stateMutability": "nonpayable"},
            ],
            "storageLayout": {
                "storage": [
                    {"label": "visible", "slot": "0", "offset": 0, "type": "t_uint256"},
                    {"label": "lastHash", "slot": "1", "offset": 0, "type": "t_uint256"},
                    {"label": "secret", "slot": "2", "offset": 0, "type": "t_uint256"},
                    {"label": "paused", "slot": "3", "offset": 0, "type": "t_bool"},
                    {"label": "credits", "slot": "4", "offset": 0, "type": "t_mapping"},
                    {"label": "position", "slot": "5", "offset": 0, "type": "t_struct"},
                ],
                "types": {
                    "t_uint256": {"encoding": "inplace", "label": "uint256", "numberOfBytes": "32"},
                    "t_bool": {"encoding": "inplace", "label": "bool", "numberOfBytes": "1"},
                    "t_mapping": {"encoding": "mapping", "label": "mapping(address => uint256)", "numberOfBytes": "32", "key": "t_address", "value": "t_uint256"},
                    "t_struct": {"encoding": "inplace", "label": "struct Foo.Position", "numberOfBytes": "32", "members": [{"label": "amount", "slot": "0", "offset": 0, "type": "t_uint256"}]},
                    "t_address": {"encoding": "inplace", "label": "address", "numberOfBytes": "20"},
                },
            },
            "methodIdentifiers": {"visible()": "0x11111111", "writeSecret(uint256)": "0x22222222"},
        }
        artifact_path = root / "out" / "Foo.sol" / "Foo.json"
        artifact_path.parent.mkdir(parents=True)
        artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
        config = {
            "target": target, "target_contract": "Foo",
            "abi_paths": {target: str(artifact_path)}, "project_roots": {target: str(root)},
            "aliases": {}, "targets": {}, "rpc": None,
        }
        return tmp, root, config

    def test_source_index_extracts_visibility_and_default_internal(self):
        source = """
        contract Foo {
            uint256 public visible;
            uint256 lastHash;
            uint256 private secret;
            uint256 public constant LIMIT = 10;
            uint256 private immutable FACTOR = 2;
            function write(uint256 value) external { secret = value; }
        }
        """
        variables = {item["name"]: item for item in lk._solidity_state_variable_index(source, "Foo")}
        self.assertEqual(variables["visible"]["visibility"], "public")
        self.assertEqual(variables["lastHash"]["visibility"], "internal")
        self.assertEqual(variables["secret"]["visibility"], "private")
        self.assertTrue(variables["LIMIT"]["constant"])
        self.assertTrue(variables["FACTOR"]["immutable"])
        self.assertNotIn("value", variables)

    def test_function_inventory_lists_state_and_visibility(self):
        tmp, root, config = self._fixture()
        previous = os.getcwd()
        output = io.StringIO()
        try:
            os.chdir(root)
            with patch.object(lk, "cast_output", return_value=(1, "", "")), contextlib.redirect_stdout(output):
                code = lk.run_functions(config, [])
        finally:
            os.chdir(previous)
            tmp.cleanup()
        rendered = output.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("STATE VARIABLES: 8", rendered)
        self.assertIn("lastHash", rendered)
        self.assertIn("internal", rendered)
        self.assertIn("secret", rendered)
        self.assertIn("private", rendered)
        self.assertIn("visible", rendered)
        self.assertIn("ABI GETTER", rendered)
        self.assertIn("LIMIT", rendered)
        self.assertIn("COMPILE-TIME", rendered)
        self.assertIn("FACTOR", rendered)
        self.assertIn("DEPLOYED CODE", rendered)

    def test_visibility_filter_includes_private_state_variables(self):
        tmp, root, config = self._fixture()
        previous = os.getcwd()
        output = io.StringIO()
        try:
            os.chdir(root)
            with patch.object(lk, "cast_output", return_value=(1, "", "")), contextlib.redirect_stdout(output):
                code = lk.run_functions(config, ["-V", "private"])
        finally:
            os.chdir(previous)
            tmp.cleanup()
        rendered = output.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("secret", rendered)
        self.assertIn("credits", rendered)
        self.assertNotIn("lastHash", rendered)
        self.assertNotIn("visible", rendered)

    def test_read_internal_scalar_uses_compiled_slot_and_reports_visibility(self):
        tmp, root, config = self._fixture()
        previous = os.getcwd()
        output = io.StringIO()
        raw = "0x" + format(42, "064x")
        try:
            os.chdir(root)
            with patch.object(lk, "_target_health_block", return_value=None), patch.object(
                lk, "run_cast", return_value=lk.CommandResult(raw, 0)
            ) as cast, contextlib.redirect_stdout(output):
                code = lk.run_state_variable_read(config, ["lastHash"])
        finally:
            os.chdir(previous)
            tmp.cleanup()
        self.assertEqual(code, 0)
        cast.assert_called_once()
        self.assertEqual(cast.call_args.args[0], ["st", "1"])
        rendered = output.getvalue()
        self.assertIn("Name:       lastHash", rendered)
        self.assertIn("Visibility: internal", rendered)
        self.assertIn("Value:      42", rendered)
        self.assertIn("does not hide on-chain storage", rendered)

    def test_public_getter_is_left_on_abi_call_path(self):
        tmp, root, config = self._fixture()
        previous = os.getcwd()
        try:
            os.chdir(root)
            with patch.object(lk, "run_cast") as cast:
                result = lk.run_state_variable_read(config, ["visible"])
        finally:
            os.chdir(previous)
            tmp.cleanup()
        self.assertIsNone(result)
        cast.assert_not_called()

    def test_composite_mapping_is_not_misreported_as_a_scalar(self):
        tmp, root, config = self._fixture()
        previous = os.getcwd()
        output = io.StringIO()
        try:
            os.chdir(root)
            with contextlib.redirect_stderr(output):
                result = lk.run_state_variable_read(config, ["credits"])
        finally:
            os.chdir(previous)
            tmp.cleanup()
        self.assertNotEqual(result, 0)
        self.assertIn("composite", output.getvalue())
        self.assertIn("lk mapping", output.getvalue())

    def test_unknown_name_falls_back_to_normal_abi_resolution(self):
        tmp, root, config = self._fixture()
        previous = os.getcwd()
        try:
            os.chdir(root)
            result = lk.run_state_variable_read(config, ["notAStateVariable"])
        finally:
            os.chdir(previous)
            tmp.cleanup()
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
