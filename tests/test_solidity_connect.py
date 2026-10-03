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
    connection_route,
    canonicalize,
    connection_meaning,
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

    def test_generic_route_covers_every_requested_concept(self):
        concepts = [
            "mapping",
            "keccak256",
            "abi.decode",
            "ecrecover",
            "nonce",
            "events",
        ]
        route = connection_route(concepts)
        for concept in concepts:
            self.assertIn(solidity_cheatsheet.canonicalize(concept), route)
        result, output = self.render("connect", *concepts)
        self.assertEqual(result, 0)
        self.assertIn("CONNECTION ROUTE", output)
        for concept in ("mapping", "keccak256", "abi.decode", "ecrecover", "nonce", "events"):
            self.assertIn(solidity_cheatsheet.canonicalize(concept), output)

    def test_deep_reference_atoms_are_composable(self):
        cases = [
            ("create2", "keccak256", "init-code", "address"),
            ("address.code", "extcodecopy", "extcodehash"),
            ("caller", "msg.sender", "callvalue", "msg.value"),
            ("mload", "mstore", "mcopy", "memory"),
            ("sload", "sstore", "mapping-slots", "storage"),
            ("tload", "tstore", "transient-storage", "reentrancy"),
            ("log1", "events", "event-indexed", "keccak256"),
        ]
        for concepts in cases:
            with self.subTest(concepts=concepts):
                result, output = self.render("connect", *concepts)
                self.assertEqual(result, 0)
                self.assertIn("CONNECTION ROUTE", output)
                self.assertNotIn("UniversalConnectionLab", output)

    def test_production_pattern_scenes_exist(self):
        scenes = [
            ("erc20-pattern", "mapping", "nested-mapping", "events"),
            ("erc721-pattern", "mapping", "address", "events"),
            ("permit-pattern", "structs", "mapping", "keccak256", "ecrecover", "nonce"),
            ("script-deploy", "constructor", "new", "script-env"),
            ("create2", "keccak256", "init-code"),
        ]
        for concepts in scenes:
            with self.subTest(concepts=concepts):
                self.assertIsNotNone(find_micro_scene(concepts))

    def test_new_reference_aliases_are_known(self):
        for term in (
            "abi.encodeWithSelector",
            "abi.encodeWithSignature",
            "abi.encodeCall",
            "error-selector",
            "create2",
            "salt",
            "address.code",
            "address.codehash",
            "caller",
            "callvalue",
            "selfbalance",
            "mcopy",
            "extcodecopy",
            "ecrecover",
            "nonce",
            "erc20",
            "erc721",
            "permit2",
        ):
            self.assertTrue(is_known_concept(term), term)



    def test_final_reference_crosscheck_matrix(self):
        # These are deliberately tiny connections that are easy to lose when
        # expanding the graph. Every one must have a path and a focused scene.
        required_pairs = [
            ("mapping", "abi.decode"),
            ("mapping", "keccak256"),
            ("abi.encode", "abi.decode"),
            ("function-signature", "function-selector"),
            ("function-selector", "msg.sig"),
            ("function-selector", "msg.data"),
            ("function-selector", "abi.encodeWithSelector"),
            ("function-signature", "abi.encodeWithSignature"),
            ("abi.encodeCall", "interface"),
            ("call", "returndata"),
            ("returndata", "abi.decode"),
            ("errors", "returndata"),
            ("event-indexed", "keccak256"),
            ("public-getter", "mapping"),
            ("struct-abi", "tuples"),
            ("struct-abi", "abi.decode"),
            ("receiver-hook", "reentrancy"),
            ("erc1271", "signature-verification"),
            ("erc20-pattern", "token-approval"),
            ("erc20-pattern", "mapping"),
            ("erc721-pattern", "receiver-hook"),
            ("erc1155-pattern", "batch-transfer"),
            ("permit-pattern", "nonce"),
            ("eip712-pattern", "block.chainid"),
            ("multisig-pattern", "threshold"),
            ("multisig-pattern", "call"),
            ("timelock-pattern", "block.timestamp"),
            ("governor-pattern", "arrays"),
            ("proxy-upgrade-pattern", "erc1967-storage"),
            ("erc1967-storage", "storage-slot"),
            ("delegatecall", "storage-layout"),
            ("create2", "init-code"),
            ("init-code", "runtime-code"),
            ("address.code", "extcodesize"),
            ("address.codehash", "extcodehash"),
            ("caller", "msg.sender"),
            ("callvalue", "msg.value"),
            ("mload", "memory"),
            ("sload", "storage-slot"),
            ("tload", "transient-storage"),
            ("tstore", "reentrancy"),
            ("vm-prank", "msg.sender"),
            ("vm-deal", "contract-balance"),
            ("vm-load", "mapping-slots"),
            ("vm-store", "mapping-slots"),
            ("vm-etch", "address.code"),
        ]

        for left, right in required_pairs:
            with self.subTest(left=left, right=right):
                self.assertTrue(
                    solidity_cheatsheet.connection_paths([left, right]),
                    f"No graph route for {left} -> {right}",
                )
                self.assertIsNotNone(
                    solidity_cheatsheet.find_micro_scene([left, right]),
                    f"No teaching scene for {left} + {right}",
                )

    def test_deep_research_aliases_are_known(self):
        aliases = [
            "abi.encodeWithSelector",
            "abi.encodeWithSignature",
            "abi.encodeCall",
            "function-overloading",
            "parameter-vs-argument",
            "event-indexed",
            "public-getter",
            "struct-abi",
            "receiver-hook",
            "erc1271",
            "erc20",
            "erc721",
            "erc1155",
            "permit",
            "eip712",
            "multisig",
            "timelock",
            "governor",
            "uups",
            "erc1967",
            "storage-slot",
            "create2",
            "init-code",
            "runtime-code",
            "address.code",
            "address.codehash",
            "block.chainid",
            "blockhash",
            "blobhash",
            "selfbalance",
            "caller",
            "callvalue",
            "mcopy",
            "pc",
            "msize",
            "memoryguard",
            "verbatim",
            "datasize",
            "dataoffset",
            "datacopy",
            "linkersymbol",
            "tuples",
            "named-arguments",
            "call-options",
        ]
        unknown = [name for name in aliases if not solidity_cheatsheet.is_known_concept(name)]
        self.assertEqual(unknown, [])

    def test_every_recognized_pair_can_be_connected(self):
        nodes = set()
        for name, aliases, _category, _meaning in self.catalog:
            nodes.add(solidity_cheatsheet.canonicalize(name))
            for alias in aliases:
                nodes.add(solidity_cheatsheet.canonicalize(alias))

        nodes.discard("symbols")
        nodes.discard("keywords")

        # The graph is a learning navigator, so every recognized concept pair
        # should at least produce a route rather than dropping to "unknown".
        sample = sorted(nodes)
        root = sample[0]
        for node in sample:
            with self.subTest(node=node):
                if node == root:
                    continue
                self.assertTrue(
                    solidity_cheatsheet.connection_paths([root, node]),
                    f"No route from {root} to {node}",
                )

    def test_final_graph_has_no_weak_nodes(self):
        audit = solidity_cheatsheet._FINAL_GRAPH_AUDIT_RESULT
        self.assertEqual(
            audit["weak_nodes"],
            [],
            f"Concepts with no semantic neighbor: {audit['weak_nodes']}",
        )
        self.assertGreaterEqual(audit["edges"], 700)
        self.assertGreaterEqual(audit["scenes"], 40)

    def test_scene_selection_prefers_exact_missed_connection(self):
        result, output = self.render(
            "connect", "mapping", "keccak256", "abi.decode"
        )
        self.assertEqual(result, 0)
        self.assertIn("decode/hash/mapping", output)
        self.assertIn("abi.decode(raw, (address))", output)
        self.assertIn("keccak256(raw)", output)
        self.assertNotIn("UniversalConnectionLab", output)


    def test_protocol_patterns_have_curated_routes(self):
        patterns = [
            ("erc20-pattern", "token-approval", "ERC20: balance + allowance + transfer"),
            ("erc721-pattern", "receiver-hook", "ERC721: tokenId"),
            ("erc1155-pattern", "batch-transfer", "ERC1155: tokenId"),
            ("eip712-pattern", "block.chainid", "EIP712: typed struct"),
            ("timelock-pattern", "block.timestamp", "Timelock: operation hash"),
            ("governor-pattern", "arrays", "Governor: proposal payload arrays"),
            ("multisig-pattern", "nonce", "Multisig: nonce"),
            ("proxy-upgrade-pattern", "erc1967-storage", "Upgrade proxy"),
            ("public-getter", "interface", "Public getter"),
            ("mapping-abi", "mapping", "Mapping is storage"),
        ]
        for left, right, title_fragment in patterns:
            with self.subTest(left=left, right=right):
                scene = solidity_cheatsheet.find_micro_scene([left, right])
                self.assertIsNotNone(scene)
                self.assertIn(title_fragment.split()[0], scene["title"])

    def test_abi_type_boundaries_are_explicit(self):
        pairs = [
            ("struct-abi", "tuples"),
            ("abi-types", "structs"),
            ("abi-types", "enum"),
            ("abi-types", "contract-types"),
            ("abi-types", "user-defined-value-types"),
            ("mapping-abi", "public-getter"),
            ("constructor", "init-code"),
            ("constructor", "function-selector"),
            ("receive", "function-selector"),
            ("fallback", "function-selector"),
            ("events", "log-topics"),
            ("errors", "error-selector"),
        ]
        for left, right in pairs:
            with self.subTest(left=left, right=right):
                self.assertTrue(
                    solidity_cheatsheet.connection_paths([left, right]),
                    f"No route for ABI boundary pair {left} -> {right}",
                )


    def test_connect_output_shows_route_not_a_universal_dump(self):
        result, output = self.render(
            "connect", "timelock-pattern", "keccak256",
            "mapping", "block.timestamp", "call"
        )
        self.assertEqual(result, 0)
        self.assertIn("CONNECTION ROUTE", output)
        self.assertNotIn("UniversalConnectionLab", output)

    def test_connect_list_advertises_real_connection_families(self):
        result, output = self.render("connect", "--list")
        self.assertEqual(result, 0)
        for token in (
            "data / ABI path",
            "call / dispatch path",
            "error / event path",
            "token path",
            "authorization path",
            "protocol lifecycle path",
            "storage / Yul path",
            "Foundry path",
        ):
            self.assertIn(token, output)

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
