import io
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from lowkey import solidity_cheatsheet
from lowkey.solidity_cheat_topics import register_topics
from lowkey.solidity_connect_data import (
    CONNECTION_LABS,
    COMPREHENSIVE_MICRO_SCENES,
    UNIVERSAL_CONNECTION_LAB,
    _COMPREHENSIVE_CONNECTION_EDGES,
    find_micro_scene,
    is_known_concept,
)


class SolidityConnectTests(unittest.TestCase):
    def render(self, *args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            result = solidity_cheatsheet.run(list(args))
        return result, buf.getvalue()

    @classmethod
    def setUpClass(cls):
        cls.catalog = []

        def capture(name, aliases, category, meaning, *args, **kwargs):
            cls.catalog.append((name, aliases, category, meaning))

        register_topics(capture)

    def test_default_connect_is_progressive_not_the_full_universal_contract(self):
        result, output = self.render(
            "connect", "interface", "functions", "arrays"
        )
        self.assertEqual(result, 0)
        self.assertIn("THE CONNECTION", output)
        self.assertIn("TINY CONNECTED EXAMPLE", output)
        self.assertIn("VARIABLES IN THIS EXAMPLE", output)
        self.assertIn("FOLLOW THE VALUE", output)
        self.assertIn("IUserStore", output)
        self.assertIn("address[] memory", output)
        self.assertNotIn("contract UniversalConnectionLab", output)

    def test_full_mode_is_explicit(self):
        result, output = self.render(
            "connect", "interface", "functions", "arrays", "1"
        )
        self.assertEqual(result, 0)
        self.assertIn("FULL CONNECTION LAB", output)
        self.assertIn("UniversalConnectionLab", output)

    def test_aliases_are_not_exposed_to_the_learner(self):
        result, output = self.render("connect", "interface", "functions")
        self.assertEqual(result, 0)
        self.assertIn("  interface", output)
        self.assertIn("  function", output)
        self.assertNotIn("functions -> function", output)

    def test_data_structure_bundle_is_the_requested_small_scene(self):
        result, output = self.render(
            "connect", "structs", "mappings", "arrays",
            "enums", "bytes", "addresses"
        )
        self.assertEqual(result, 0)
        for token in (
            "mapping(address => Profile)",
            "mapping(address => mapping(bytes32 => uint256))",
            "uint256[]",
            "address[]",
            "Status",
            "bytes calldata",
            "address user_",
            "Profile storage",
            "balances[user_][id_]",
        ):
            self.assertIn(token, output)
        self.assertNotIn("UniversalConnectionLab", output)

    def test_import_constructor_bundle_explains_base_and_child_inputs(self):
        result, output = self.render("connect", "imports", "constructor")
        self.assertEqual(result, 0)
        for token in (
            "Import → base/interface → constructor chain",
            'import "./Owned.sol";',
            "Owned(msg.sender)",
            "owner_",
            "name_",
            'new Vault("Savings");',
        ):
            self.assertIn(token, output)

    def test_interface_function_aliases_resolve_to_the_same_concept(self):
        for term in (
            "functions",
            "function-syntax",
            "function-call",
            "function",
        ):
            result, output = self.render("connect", "interface", term)
            self.assertEqual(result, 0)
            self.assertIn("An interface call returns an array", output)

    def test_aliases_work_for_plural_data_terms(self):
        result, output = self.render(
            "connect", "struct", "mapping", "dynamic-array",
            "static-array", "enum"
        )
        self.assertEqual(result, 0)
        self.assertIn("Address → struct → enum/bytes/array → nested mapping", output)

    def test_mapping_decode_hash_connection_is_not_fallback_graph_noise(self):
        result, output = self.render(
            "connect", "mapping", "keccak256", "abi.decode"
        )
        self.assertEqual(result, 0)
        self.assertIn(
            "Decode the bytes, hash the same bytes, use the hash as the key",
            output,
        )
        self.assertIn("owners[id]", output)
        self.assertIn("abi.decode(raw, (address))", output)
        self.assertIn("keccak256(raw)", output)
        self.assertNotIn("UniversalConnectionLab", output)

    def test_mapping_keccak_scene_does_not_smuggle_in_abi_encode(self):
        result, output = self.render("connect", "mapping", "keccak256")
        self.assertEqual(result, 0)
        self.assertIn("A hash becomes a mapping key", output)
        self.assertNotIn("Encode → hash → mapping key", output)
        self.assertNotIn("abi.encode(user_, amount_)", output)

    def test_mapping_decode_pair_has_a_teaching_scene(self):
        result, output = self.render("connect", "mapping", "abi.decode")
        self.assertEqual(result, 0)
        self.assertIn("Decode first, then use the decoded value as a key", output)
        self.assertIn("balances[user_]", output)

    def test_list_exposes_the_comprehensive_graph_and_featured_paths(self):
        result, output = self.render("connect", "--list")
        self.assertEqual(result, 0)
        self.assertIn("CONNECTION LABS", output)
        self.assertIn("solidity-yul-comprehensive-graph", output)
        self.assertIn("decode/hash/mapping", output)
        self.assertIn("ABI call path", output)
        self.assertIn("proxy flow", output)

    def test_arbitrary_known_combinations_are_graph_backed_but_progressive(self):
        cases = [
            ("interface", "mapping", "arrays"),
            ("imports", "interface"),
            ("mapping", "keccak256", "abi.encode"),
            ("yul", "mapping", "keccak256"),
            ("functions", "interface", "arrays"),
            ("interface", "mapping", "yul", "ecrecover"),
        ]
        for terms in cases:
            with self.subTest(terms=terms):
                result, output = self.render("connect", *terms)
                self.assertEqual(result, 0)
                self.assertIn("LOWKEY // CONNECT", output)
                self.assertIn("THE CONNECTION", output)
                self.assertIn("NEXT", output)
                self.assertNotIn("UniversalConnectionLab", output)

    def test_yul_topics_are_composable(self):
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
            self.assertIn("LOWKEY // CONNECT", output)
            self.assertIn("THE CONNECTION", output)

    def test_every_catalog_topic_and_alias_is_known(self):
        unknown = []
        for name, aliases, _, _ in self.catalog:
            if not is_known_concept(name):
                unknown.append(name)
            for alias in aliases:
                if not is_known_concept(alias):
                    unknown.append(alias)
        self.assertEqual(
            unknown,
            [],
            f"Connect does not recognize these catalog concepts/aliases: {unknown}",
        )

    def test_every_catalog_topic_is_in_the_same_connection_component(self):
        nodes = {solidity_cheatsheet.canonicalize(name) for name, _, _, _ in self.catalog}
        adjacency = {node: set() for node in nodes}

        for left, right, _ in _COMPREHENSIVE_CONNECTION_EDGES:
            a = solidity_cheatsheet.canonicalize(left)
            b = solidity_cheatsheet.canonicalize(right)
            if a in nodes:
                adjacency[a].add(b)
            if b in nodes:
                adjacency[b].add(a)

        isolated = sorted(node for node, neighbors in adjacency.items() if not neighbors)
        self.assertEqual(isolated, [], f"Isolated catalog concepts: {isolated}")

        start = next(iter(nodes))
        seen = {start}
        stack = [start]
        while stack:
            node = stack.pop()
            for nxt in adjacency.get(node, ()):
                if nxt in nodes and nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)

        self.assertEqual(
            sorted(nodes - seen),
            [],
            "Every catalog concept must be reachable through the connection graph.",
        )

    def test_plain_keccak_meaning_does_not_leak_selector_language(self):
        meaning = connection_meaning("keccak256").lower()
        self.assertIn("hash", meaning)
        self.assertNotIn("function selector", meaning)

    def test_modern_reference_primitives_are_known_and_connected(self):
        primitives = [
            "abi.encodeCall",
            "abi.encodeWithSelector",
            "function-types",
            "contract-types",
            "user-defined-value-types",
            "transient-storage",
            "erc7201",
            "ecrecover",
            "sha256",
            "ripemd160",
            "addmod",
            "mulmod",
            "bytes.concat",
            "string.concat",
            "nonce",
            "selfdestruct",
            "address.code",
            "address.codehash",
            "block.chainid",
            "block.basefee",
            "block.prevrandao",
            "mload",
            "mstore",
            "sload",
            "sstore",
            "tload",
            "tstore",
            "calldataload",
            "returndatacopy",
            "log4",
        ]
        for name in primitives:
            self.assertTrue(is_known_concept(name), name)
        edge_nodes = set()
        for left, right, _ in _COMPREHENSIVE_CONNECTION_EDGES:
            edge_nodes.add(canonicalize(left))
            edge_nodes.add(canonicalize(right))
        for name in primitives:
            self.assertIn(canonicalize(name), edge_nodes, name)

    def test_graph_and_scene_depth(self):
        self.assertGreaterEqual(len(_COMPREHENSIVE_CONNECTION_EDGES), 250)
        self.assertGreaterEqual(len(COMPREHENSIVE_MICRO_SCENES), 30)

    def test_high_value_multi_hop_scenes_exist(self):
        cases = [
            ["mapping", "abi.decode"],
            ["mapping", "keccak256"],
            ["mapping", "keccak256", "abi.decode"],
            ["abi.encode", "abi.decode", "keccak256"],
            ["function-signature", "function-selector", "calldata", "abi.decode"],
            ["function-selector", "abi.encodeWithSelector", "abi.encodeCall", "function-types"],
            ["events", "event-indexed", "keccak256"],
            ["receive", "fallback", "payable", "msg.value", "call"],
            ["require", "revert", "assert", "custom-errors", "try-catch"],
            ["modifier", "access-control", "mapping", "msg.sender", "enum", "events"],
            ["proxy-fallback", "fallback", "delegatecall", "storage-layout", "returndata"],
            ["transient-storage", "reentrancy", "storage", "yul"],
            ["erc7201", "custom-storage-layout", "structs", "mapping", "keccak256", "yul-storage"],
            ["new", "constructor", "address", "try-catch"],
            ["vm-expect-call", "calls", "abi.encode", "test"],
            ["fuzz-tests", "bounded-fuzz", "vm-assume", "vm-bound"],
            ["poc-reentrancy", "reentrancy", "call", "receive", "mapping"],
        ]
        for concepts in cases:
            with self.subTest(concepts=concepts):
                self.assertIsNotNone(
                    find_micro_scene(concepts),
                    f"No teaching scene for {concepts}",
                )

    def test_current_solidity_reference_helpers_are_known(self):
        expected = [
            "abi.encodeCall",
            "function-types",
            "contract-types",
            "user-defined-value-types",
            "transient-storage",
            "erc7201",
            "ecrecover",
            "sha256",
            "ripemd160",
            "addmod",
            "mulmod",
            "bytes.concat",
            "string.concat",
            "nonce",
            "selfdestruct",
        ]
        unknown = [name for name in expected if not is_known_concept(name)]
        self.assertEqual(unknown, [])

    def test_specific_tiny_connections_are_not_lost(self):
        pairs = [
            ("mapping", "keccak256"),
            ("mapping", "abi.decode"),
            ("abi.encode", "abi.decode"),
            ("abi.decode", "keccak256"),
            ("call", "returndata"),
            ("fallback", "msg.sig"),
            ("events", "event-indexed"),
            ("transient-storage", "reentrancy"),
            ("vm-prank", "msg.sender"),
            ("vm-deal", "contract-balance"),
            ("vm-expect-call", "calls"),
            ("poc-signature", "nonce"),
        ]
        for left, right in pairs:
            with self.subTest(left=left, right=right):
                paths = solidity_cheatsheet.connection_paths([left, right])
                self.assertTrue(paths, f"No graph path for {left} -> {right}")

    def test_universal_connection_lab_compiles(self):
        if shutil.which("forge") is None:
            self.skipTest("Forge is required for connection-lab compiler coverage.")

        with tempfile.TemporaryDirectory(prefix="lowkey-connect-universal-") as td:
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
            (src / "UniversalConnectionLab.sol").write_text(
                UNIVERSAL_CONNECTION_LAB["source"],
                encoding="utf-8",
            )
            for filename, source in UNIVERSAL_CONNECTION_LAB.get(
                "support_files", {}
            ).items():
                (src / filename).write_text(source, encoding="utf-8")

            proc = subprocess.run(
                ["forge", "build", "--root", str(root)],
                text=True,
                capture_output=True,
            )
            self.assertEqual(
                proc.returncode,
                0,
                f"Universal connection lab failed to compile:\n"
                f"{proc.stdout}\n{proc.stderr}",
            )

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
