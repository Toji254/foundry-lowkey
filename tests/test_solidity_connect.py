import io
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from lowkey.solidity_connect_data import CONNECTION_LABS
from lowkey import solidity_cheatsheet


class SolidityConnectTests(unittest.TestCase):
    def render(self, *args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            result = solidity_cheatsheet.run(list(args))
        return result, buf.getvalue()

    def test_big_data_connection_shows_requested_concepts_and_variables(self):
        result, output = self.render(
            "connect", "structs", "mappings", "arrays", "enums", "bytes", "addresses"
        )
        self.assertEqual(result, 0)
        for token in (
            "LOWKEY // CONNECT",
            "CONNECTION LAB",
            "data-structures",
            "mapping(address => Profile)",
            "mapping(address => mapping(bytes32 => uint256))",
            "address[]",
            "address[3]",
            "uint256[]",
            "uint256[3]",
            "bytes32",
            "Status",
            "string calldata",
            "Profile storage",
            "msg.sender",
            "createProfile",
            "updateProfile",
            "balances[user_][id_]",
            "push",
            "HOW THE PIECES CONNECT",
            "CONNECTION MAP",
            "AUDIT LOOKOUT",
        ):
            self.assertIn(token, output)

    def test_import_and_constructor_connection_shows_both_argument_paths(self):
        result, output = self.render("connect", "import", "constructor")
        self.assertEqual(result, 0)
        for token in (
            "import-constructor",
            'import "./Owned.sol";',
            "constructor(string memory name_, uint256 limit_)",
            "Owned(msg.sender)",
            "constructor parameter",
            "base-constructor argument",
            'new Vault("Savings", 1000);',
            "name_",
            "limit_",
            "owner_",
        ):
            self.assertIn(token, output)

    def test_function_topic_aliases_connect_to_interface_lab(self):
        for term in ("functions", "function-syntax", "function-signature", "function-call"):
            result, output = self.render("connect", "interface", term)
            self.assertEqual(result, 0)
            self.assertIn("external-interfaces", output)
            self.assertIn("ICounter", output)

    def test_three_or_more_concepts_select_a_bundle(self):
        result, output = self.render(
            "connect", "interface", "external-call", "abi-decode", "address"
        )
        self.assertEqual(result, 0)
        for token in (
            "external-interfaces",
            "ICounter",
            "staticcall",
            "abi.decode",
            "address",
            "target_",
        ):
            self.assertIn(token, output)

    def test_aliases_work_for_plural_data_terms(self):
        result, output = self.render(
            "connect", "struct", "mapping", "dynamic-array", "static-array", "enum"
        )
        self.assertEqual(result, 0)
        self.assertIn("data-structures", output)

    def test_connection_list_exists(self):
        result, output = self.render("connect", "--list")
        self.assertEqual(result, 0)
        self.assertIn("CONNECTION LABS", output)
        for lab in CONNECTION_LABS:
            self.assertIn(lab["name"], output)

    def test_missing_connection_is_explicit_not_silently_wrong(self):
        result, output = self.render("connect", "for", "delegatecall")
        self.assertEqual(result, 2)
        self.assertIn("No single connection lab currently covers", output)
        self.assertIn("lk connect --list", output)

    def test_arbitrary_known_combinations_use_universal_composer(self):
        cases = [
            ("interface", "mapping", "arrays"),
            ("imports", "interface"),
            ("mapping", "keccak256", "abi.encode"),
            ("yul", "mapping", "keccak256"),
            ("functions", "interface", "arrays"),
        ]
        for terms in cases:
            with self.subTest(terms=terms):
                result, output = self.render("connect", *terms)
                self.assertEqual(result, 0)
                self.assertIn("LOWKEY // CONNECT", output)
                self.assertIn("solidity-yul-composer", output)
                self.assertIn("CONNECTION MAP", output)

    def test_function_alias_is_displayed_as_function(self):
        result, output = self.render("connect", "interface", "functions")
        self.assertEqual(result, 0)
        self.assertIn("functions -> function", output)
        self.assertNotIn("functions -> function-syntax", output)

    def test_yul_topics_exist(self):
        for topic in (
            "yul",
            "yul-memory",
            "yul-storage",
            "yul-calldata",
            "yul-control-flow",
            "yul-functions",
            "yul-call",
        ):
            result, output = self.render("connect", topic, "mapping")
            self.assertEqual(result, 0)
            self.assertIn("CONNECTION LAB", output)

    def test_every_connection_lab_compiles(self):
        if shutil.which("forge") is None:
            self.skipTest("Forge is required for connection-lab compiler coverage.")
        for lab in CONNECTION_LABS:
            with self.subTest(lab=lab["name"]), tempfile.TemporaryDirectory(
                prefix=f"lowkey-connect-{lab['name']}-"
            ) as td:
                root = Path(td)
                src = root / "src"
                src.mkdir()

                (root / "foundry.toml").write_text(
                    """[profile.default]
src = "src"
solc_version = "0.8.20"
""",
                    encoding="utf-8",
                )

                safe = "".join(
                    ch if ch.isalnum() else "_" for ch in lab["name"]
                )
                (src / f"{safe}.sol").write_text(
                    lab["source"],
                    encoding="utf-8",
                )

                for filename, source in lab.get("support_files", {}).items():
                    (src / filename).write_text(source, encoding="utf-8")

                proc = subprocess.run(
                    ["forge", "build", "--root", str(root)],
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(
                    proc.returncode,
                    0,
                    f"Connection lab {lab['name']} failed to compile:\n"
                    f"{proc.stdout}\n{proc.stderr}",
                )


if __name__ == "__main__":
    unittest.main()
