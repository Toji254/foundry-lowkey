import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
if str(LOWKEY) not in sys.path:
    sys.path.insert(0, str(LOWKEY))

from source_index import build_source_index
from source_link import _link_parser, main, render_link, run_flow
from source_graph import build_protocol_graph


class SourceLinkTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(temporary.name)
        (root / "src").mkdir()
        (root / "foundry.toml").write_text(
            "\n".join([
                "[profile.default]",
                'src = "src"',
                'remappings = ["@audit/=lib/audit/"]',
                "",
            ]),
            encoding="utf-8",
        )
        (root / "lib" / "audit" / "ImportedMath.sol").parent.mkdir(parents=True)
        (root / "lib" / "audit" / "ImportedMath.sol").write_text(
            """
            pragma solidity ^0.8.20;
            library ImportedMath {
                function plus(uint256 value, uint256 amount) internal pure returns (uint256) {
                    return value + amount;
                }
            }
            """,
            encoding="utf-8",
        )
        (root / "src" / "BaseLink.sol").write_text(
            """
            pragma solidity ^0.8.20;
            abstract contract BaseLink {
                uint256 public inheritedSeed = 7;
                address public baseOwner;
                constructor() {
                    baseOwner = msg.sender;
                }
                function baseAction() public virtual {}
            }
            """,
            encoding="utf-8",
        )
        (root / "src" / "LinkLib.sol").write_text(
            """
            pragma solidity ^0.8.20;
            library LinkLib {
                function inc(uint256 value, uint256 amount) internal pure returns (uint256) {
                    return value + amount;
                }
            }
            """,
            encoding="utf-8",
        )
        (root / "src" / "Graph.sol").write_text(
            """
            pragma solidity ^0.8.20;
            import "./BaseLink.sol";
            import "./LinkLib.sol";
            import "@audit/ImportedMath.sol";
            contract Graph is BaseLink {
                using LinkLib for uint256;
                using ImportedMath for uint256;
                struct Position { address owner; uint256 collateral; uint256 debt; }
                mapping(address => uint256) public balances;
                mapping(address => mapping(uint256 => Position)) public positions;
                event Paid(address indexed user, uint256 amount);
                function deposit() external payable {
                    balances[msg.sender] += msg.value;
                }
                function baseAction() public override {}
                function setPosition(uint256 id) external { positions[msg.sender][id].debt = 1; }
                function getPosition(uint256 id) external view returns (uint256) { return positions[msg.sender][id].debt; }
                function thirdPartyUse(uint256 value) external pure returns (uint256) {
                    return value.plus(1);
                }
                function libraryUse(uint256 value) external pure returns (uint256) {
                    return value.inc(1);
                }
                function withdraw(uint256 amount) external {
                    _debit(msg.sender, amount);
                    (bool ok,) = payable(msg.sender).call{value: amount}("");
                    require(ok);
                    emit Paid(msg.sender, amount);
                }
                function _debit(address user, uint256 amount) internal {
                    _recordDebit(user, amount);
                    balances[user] -= amount;
                }
                function _recordDebit(address user, uint256 amount) internal {
                    lastDebitAmount = amount;
                }
                function recurse(uint256 count) internal {
                    if (count > 0) recurse(count - 1);
                }
                uint256 public lastDebitAmount;
                function overloaded(uint256 value) internal pure returns (uint256) { return value; }
                function overloaded(address value) internal pure returns (address) { return value; }
            }
            """,
            encoding="utf-8",
        )
        return temporary, root

    def _index(self, root):
        return build_source_index(root, use_cache=False)

    def test_function_link_shows_callers_helpers_storage_and_events(self):
        temporary, root = self.fixture()
        try:
            index = self._index(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = render_link(index, "Graph.withdraw(uint256)", detail="all")
        finally:
            temporary.cleanup()
        text = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("LOWKEY // SOURCE LINK", text)
        self.assertIn("AT A GLANCE", text)
        self.assertIn("CALLS", text)
        self.assertIn("_debit(address,uint256)", text)
        self.assertIn("STORAGE WRITES", text)
        self.assertIn("ASSET FLOW / CAPABILITY", text)
        self.assertIn("ORIGIN    FIRST-PARTY", text)

    def test_bare_link_lists_available_contracts_and_how_to_explore_them(self):
        temporary, root = self.fixture()
        try:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["link", "--root", str(root), "--list"])
        finally:
            temporary.cleanup()

        rendered = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("AVAILABLE CONTRACTS", rendered)
        self.assertIn("Graph (contract)", rendered)
        self.assertIn("BaseLink (abstract contract)", rendered)
        self.assertIn("ImportedMath (library)", rendered)
        self.assertIn("src/", rendered)
        self.assertIn("Graph.sol:", rendered)
        self.assertIn("EXPLORE", rendered)
        self.assertIn("lk link ContractName.mappingName", rendered)
        self.assertNotIn("relationships=", rendered)
        self.assertLess(len(rendered.splitlines()), 45)

    def test_bare_link_defaults_to_protocol_relationship_graph(self):
        temporary, root = self.fixture()
        try:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["link", "--root", str(root)])
        finally:
            temporary.cleanup()

        rendered = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("LOWKEY // PROTOCOL GRAPH", rendered)
        self.assertIn("CONTRACT CONNECTIONS", rendered)
        self.assertIn("[Graph]", rendered)
        self.assertIn("INHERITS", rendered)
        self.assertNotIn("AVAILABLE CONTRACTS", rendered)
        self.assertNotIn("ImportedMath", rendered)

    def test_default_architecture_hides_import_edges_but_import_filter_keeps_them(self):
        temporary, root = self.fixture()
        try:
            index = build_source_index(root)
        finally:
            temporary.cleanup()

        architecture = build_protocol_graph(index)
        imports = build_protocol_graph(index, only="imports")
        self.assertFalse(any(edge["kind"] == "IMPORTS" for edge in architecture["edges"]))
        self.assertTrue(any(edge["kind"] == "IMPORTS" for edge in imports["edges"]))

    def test_library_function_calls_are_labelled_as_library_calls(self):
        index = {
            "nodes": [
                {"id": "contract:vault", "kind": "contract", "name": "Vault", "file": "src/Vault.sol", "declaration_kind": "contract"},
                {"id": "contract:math", "kind": "contract", "name": "Math", "file": "src/Math.sol", "declaration_kind": "library"},
                {"id": "function:vault", "kind": "function", "contract": "Vault", "file": "src/Vault.sol", "qualified_name": "Vault.withdraw()"},
                {"id": "function:math", "kind": "function", "contract": "Math", "file": "src/Math.sol", "qualified_name": "Math.add(uint256,uint256)"},
            ],
            "edges": [{
                "kind": "CALLS", "from": "function:vault", "to": "function:math",
                "resolution": "INFERRED", "source": {"file": "src/Vault.sol", "line": 42},
            }],
            "summary": {"files": 2, "functions": 2, "relationships": 1},
        }
        graph = build_protocol_graph(index)
        self.assertTrue(any(edge["kind"] == "LIBRARY_CALL" and edge["label"] == "LIBRARY CALL" for edge in graph["edges"]))

    def test_graph_json_contains_nodes_and_relationship_edges(self):
        temporary, root = self.fixture()
        try:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["link", "--root", str(root), "--format", "json"])
        finally:
            temporary.cleanup()

        payload = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertTrue(any(item["label"] == "Graph" for item in payload["nodes"]))
        self.assertTrue(any(item["kind"] == "INHERITS" for item in payload["edges"]))
        self.assertIn("limitations", payload)

    def test_html_graph_export_is_offline_and_writes_under_project_root(self):
        temporary, root = self.fixture()
        try:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["link", "--root", str(root), "--format", "html"])
            html_path = root / ".lowkey" / "link-graph.html"
            self.assertTrue(html_path.is_file())
            document = html_path.read_text(encoding="utf-8")
        finally:
            temporary.cleanup()

        self.assertEqual(status, 0)
        self.assertIn("GRAPH SAVED", output.getvalue())
        self.assertIn("PROTOCOL GRAPH", document)
        self.assertIn('id="graph"', document)
        self.assertIn("Architecture", document)
        self.assertIn("Function flow", document)
        self.assertIn("Asset flow", document)
        self.assertIn("project explorer", document.lower())
        self.assertIn('data-filter="interface"', document)
        self.assertIn('data-filter="library"', document)
        self.assertIn("search-results", document)
        self.assertIn("STATIC_SOURCE", document)
        self.assertNotIn("__GRAPH_DATA__", document)
        self.assertNotIn("__SERVER_MODE__", document)
        self.assertNotIn('<script src="https://', document)

    def test_focused_contract_graph_keeps_neighbourhood_and_existing_overview(self):
        temporary, root = self.fixture()
        try:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["link", "Graph", "--root", str(root), "--depth", "1"])
        finally:
            temporary.cleanup()

        rendered = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("FOCUS  Graph", rendered)
        self.assertIn("CONTRACT: Graph", rendered)
        self.assertIn("INHERITANCE", rendered)

    def test_graph_can_include_third_party_dependencies_explicitly(self):
        temporary, root = self.fixture()
        try:
            default_output = io.StringIO()
            with contextlib.redirect_stdout(default_output):
                default_status = main(["link", "--root", str(root)])
            third_party_output = io.StringIO()
            with contextlib.redirect_stdout(third_party_output):
                third_party_status = main(["link", "--root", str(root), "--include-third-party"])
        finally:
            temporary.cleanup()

        self.assertEqual(default_status, 0)
        self.assertEqual(third_party_status, 0)
        self.assertNotIn("ImportedMath", default_output.getvalue())
        self.assertIn("ImportedMath", third_party_output.getvalue())

    def test_bare_link_supports_json_project_index(self):
        temporary, root = self.fixture()
        try:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["link", "--root", str(root), "--list", "--json"])
        finally:
            temporary.cleanup()

        payload = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertGreater(payload["total_contracts"], 0)
        self.assertTrue(any(item["name"] == "Graph" for item in payload["contracts"]))

    def test_trace_source_alias_renders_a_function_call_tree(self):
        temporary, root = self.fixture()
        try:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main([
                    "trace", "source", "Graph.withdraw(uint256)",
                    "--root", str(root),
                ])
        finally:
            temporary.cleanup()
        self.assertEqual(status, 0)
        self.assertIn("AT A GLANCE", output.getvalue())
        self.assertIn("CALL CHAIN", output.getvalue())
        self.assertIn("Graph._debit(address,uint256)", output.getvalue())

    def test_mapping_link_includes_key_path_and_accessors(self):
        temporary, root = self.fixture()
        try:
            index = self._index(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = render_link(index, "Graph.balances")
        finally:
            temporary.cleanup()
        text = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("KEY TYPES", text)
        self.assertIn("address", text)
        self.assertIn("KEY EXAMPLES", text)
        self.assertIn("READ BY", text)
        self.assertIn("WRITTEN BY", text)
        self.assertIn("balances[msg.sender]", text)
        self.assertIn("balances[user]", text)
        self.assertNotIn("indexes=", text)
        self.assertNotIn("mapping-depth=", text)

    def test_nested_mapping_view_shows_key_path_readers_writers_and_struct_fields(self):
        temporary, root = self.fixture()
        try:
            index = self._index(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = render_link(index, "Graph.positions")
        finally:
            temporary.cleanup()
        rendered = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("mapping(address => mapping(uint256 => Position))", rendered)
        self.assertIn("KEY TYPES", rendered)
        self.assertIn("address -> uint256", rendered)
        self.assertIn("positions[msg.sender][id].debt", rendered)
        self.assertIn("READ BY", rendered)
        self.assertIn("getPosition(uint256)", rendered)
        self.assertIn("WRITTEN BY", rendered)
        self.assertIn("setPosition(uint256)", rendered)
        self.assertIn("STRUCT: Position", rendered)
        self.assertIn("collateral", rendered)
        self.assertIn("debt", rendered)

    def test_contract_link_shows_importable_overview(self):
        temporary, root = self.fixture()
        try:
            index = self._index(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = render_link(index, "Graph", depth=2)
        finally:
            temporary.cleanup()
        text = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("FUNCTIONS", text)
        self.assertIn("STORAGE", text)
        self.assertIn("INHERITANCE", text)
        self.assertIn("IMPORTS", text)
        self.assertNotIn("INTERNAL CALLS", text)
        self.assertNotIn("relationships=", text)
        self.assertLess(len(text.splitlines()), 65)

    def test_derived_contract_overview_includes_base_initializers_and_constructor_writes(self):
        temporary, root = self.fixture()
        try:
            index = self._index(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = render_link(index, "Graph", only="writes")
        finally:
            temporary.cleanup()

        rendered = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("STATE INITIALIZERS", rendered)
        self.assertIn("inheritedSeed", rendered)
        self.assertIn("initialization context=BaseLink", rendered)
        self.assertIn("baseOwner", rendered)
        self.assertIn("BaseLink.constructor()", rendered)

    def test_contract_reads_and_writes_filters_show_direct_and_indirect_effects(self):
        temporary, root = self.fixture()
        try:
            index = self._index(root)
            writes_output = io.StringIO()
            with contextlib.redirect_stdout(writes_output):
                writes_status = render_link(index, "Graph", only="writes")
            reads_output = io.StringIO()
            with contextlib.redirect_stdout(reads_output):
                reads_status = render_link(index, "Graph", only="reads")
        finally:
            temporary.cleanup()

        self.assertEqual(writes_status, 0)
        self.assertIn("STATE MUTATIONS / WRITES", writes_output.getvalue())
        self.assertIn("balances[user]", writes_output.getvalue())
        self.assertEqual(reads_status, 0)
        self.assertIn("STORAGE READS", reads_output.getvalue())
        self.assertIn("balances[user]", reads_output.getvalue())

    def test_imported_library_is_marked_third_party_and_linked_back_to_importer(self):
        temporary, root = self.fixture()
        try:
            index = self._index(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = render_link(index, "ImportedMath")
        finally:
            temporary.cleanup()

        self.assertEqual(status, 0)
        rendered = output.getvalue()
        self.assertIn("ORIGIN:   THIRD-PARTY", rendered)
        self.assertIn("USED BY", rendered)
        self.assertIn("Graph (contract)", rendered)
        imported_function = next(
            item for item in index["nodes"]
            if item.get("qualified_name") == "ImportedMath.plus(uint256,uint256)"
        )
        self.assertEqual(imported_function.get("provenance"), "third-party")

    def test_contract_navigation_shows_reverse_inheritance_and_library_use(self):
        temporary, root = self.fixture()
        try:
            index = self._index(root)
            base_output = io.StringIO()
            with contextlib.redirect_stdout(base_output):
                base_status = render_link(index, "BaseLink")
            library_output = io.StringIO()
            with contextlib.redirect_stdout(library_output):
                library_status = render_link(index, "LinkLib")
        finally:
            temporary.cleanup()

        self.assertEqual(base_status, 0)
        self.assertIn("INHERITED BY", base_output.getvalue())
        self.assertIn("Graph (contract)", base_output.getvalue())
        self.assertEqual(library_status, 0)
        self.assertIn("USED BY", library_output.getvalue())
        self.assertIn("Graph (contract)", library_output.getvalue())

    def test_overloaded_symbol_without_signature_is_not_guessed(self):
        temporary, root = self.fixture()
        try:
            index = self._index(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = render_link(index, "Graph.overloaded")
        finally:
            temporary.cleanup()
        self.assertEqual(status, 2)
        self.assertIn("AMBIGUOUS", output.getvalue())
        self.assertIn("overloaded(uint256)", output.getvalue())
        self.assertIn("overloaded(address)", output.getvalue())

    def test_function_link_renders_nested_call_chains_and_stops_recursion(self):
        temporary, root = self.fixture()
        try:
            index = self._index(root)
            nested_output = io.StringIO()
            with contextlib.redirect_stdout(nested_output):
                nested_status = render_link(index, "Graph.withdraw(uint256)", detail="all")
            recursive_output = io.StringIO()
            with contextlib.redirect_stdout(recursive_output):
                recursive_status = render_link(index, "Graph.recurse(uint256)", depth=5, detail="all")
        finally:
            temporary.cleanup()

        self.assertEqual(nested_status, 0)
        self.assertIn("CALL CHAIN", nested_output.getvalue())
        self.assertIn("Graph._debit(address,uint256)", nested_output.getvalue())
        self.assertIn("Graph._recordDebit(address,uint256)", nested_output.getvalue())
        self.assertEqual(recursive_status, 0)
        self.assertIn("recursive cycle; traversal stopped", recursive_output.getvalue())

    def test_constant_immutable_and_transient_views_are_labeled_separately(self):
        temporary, root = self.fixture()
        try:
            (root / "src" / "ValueKinds.sol").write_text(
                """
                pragma solidity ^0.8.20;
                contract ValueKinds {
                    uint256 public constant SCALE = 1e18;
                    uint256 public immutable deployedAt;
                    uint256 transient transientCounter;

                    constructor() {
                        deployedAt = block.timestamp;
                    }

                    function readValues() external view returns (uint256) {
                        return SCALE + deployedAt + transientCounter;
                    }
                }
                """,
                encoding="utf-8",
            )
            index = self._index(root)
            variable_output = io.StringIO()
            with contextlib.redirect_stdout(variable_output):
                variable_status = render_link(index, "ValueKinds.deployedAt")
            contract_output = io.StringIO()
            with contextlib.redirect_stdout(contract_output):
                contract_status = render_link(index, "ValueKinds")
            function_output = io.StringIO()
            with contextlib.redirect_stdout(function_output):
                function_status = render_link(index, "ValueKinds.readValues()", detail="all")
        finally:
            temporary.cleanup()

        self.assertEqual(variable_status, 0)
        self.assertIn("PERSISTENCE IMMUTABLE", variable_output.getvalue())
        self.assertIn("not an ordinary persistent EVM storage slot", variable_output.getvalue())
        self.assertEqual(contract_status, 0)
        self.assertIn("CONSTANTS / IMMUTABLES", contract_output.getvalue())
        self.assertIn("STORAGE", contract_output.getvalue())
        self.assertIn("TRANSIENT STORAGE", contract_output.getvalue())
        self.assertIn("transientCounter", contract_output.getvalue())
        self.assertEqual(function_status, 0)
        self.assertIn("CONSTANT REFERENCES", function_output.getvalue())
        self.assertIn("IMMUTABLE REFERENCES", function_output.getvalue())

    def test_bare_link_supports_search_type_filter_and_pagination(self):
        temporary, root = self.fixture()
        try:
            for name in ("Alpha", "Beta", "Gamma"):
                (root / "src" / f"{name}.sol").write_text(
                    f"pragma solidity ^0.8.20; contract {name} {{ uint256 value; }}",
                    encoding="utf-8",
                )
            page_output = io.StringIO()
            with contextlib.redirect_stdout(page_output):
                page_status = main(["link", "--root", str(root), "--limit", "2", "--page", "2"])
            search_output = io.StringIO()
            with contextlib.redirect_stdout(search_output):
                search_status = main(["link", "--root", str(root), "--search", "Graph"])
            type_output = io.StringIO()
            with contextlib.redirect_stdout(type_output):
                type_status = main(["link", "--root", str(root), "--type", "library"])
        finally:
            temporary.cleanup()

        self.assertEqual(page_status, 0)
        self.assertIn("PAGE    2/", page_output.getvalue())
        self.assertIn("showing 2 of", page_output.getvalue())
        self.assertEqual(search_status, 0)
        self.assertIn("Graph (contract)", search_output.getvalue())
        self.assertIn("showing 1 of 1", search_output.getvalue())
        self.assertEqual(type_status, 0)
        self.assertIn("ImportedMath", type_output.getvalue())
        self.assertNotIn("Graph", type_output.getvalue())

    def test_function_default_view_is_compact_and_has_clear_drilldowns(self):
        temporary, root = self.fixture()
        try:
            index = self._index(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = render_link(index, "Graph.withdraw(uint256)")
        finally:
            temporary.cleanup()

        rendered = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("LOWKEY // SOURCE TRACE", rendered)
        self.assertIn("AT A GLANCE", rendered)
        self.assertIn("CALL FLOW", rendered)
        self.assertIn("--detail calls", rendered)
        self.assertIn("--detail storage", rendered)
        self.assertLess(len(rendered.splitlines()), 40)
        self.assertNotIn("GRAPH     ", rendered)


    def test_only_filter_is_rejected_for_function_targets(self):
        temporary, root = self.fixture()
        try:
            index = self._index(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = render_link(index, "Graph.withdraw(uint256)", only="writes")
        finally:
            temporary.cleanup()

        self.assertEqual(status, 2)
        self.assertIn("--only filters contract relationships", output.getvalue())

    def test_function_details_scope_unresolved_targets_to_reachable_functions(self):
        temporary, root = self.fixture()
        try:
            index = self._index(root)
            unrelated = next(
                item for item in index["nodes"]
                if item.get("qualified_name") == "ImportedMath.plus(uint256,uint256)"
            )
            index["edges"].append({
                "id": "UNRESOLVED:unrelated-number-sub",
                "kind": "CALLS",
                "from": unrelated["id"],
                "to": "external:number.sub",
                "resolution": "UNRESOLVED",
                "source": {"file": "lib/audit/ImportedMath.sol", "line": 7, "column": 1},
                "detail": "Unrelated library call used only to prove scope isolation.",
            })
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = render_link(index, "Graph.withdraw(uint256)", detail="all")
        finally:
            temporary.cleanup()

        rendered = output.getvalue()
        self.assertEqual(status, 0)
        self.assertNotIn("number.sub", rendered)
        self.assertIn("UNRESOLVED TARGETS", rendered)
        self.assertIn("reachable scope", rendered)

    def test_function_storage_detail_groups_accesses_by_state_declaration(self):
        temporary, root = self.fixture()
        try:
            index = self._index(root)
            getter = next(
                item for item in index["nodes"]
                if item.get("qualified_name") == "Graph.getPosition(uint256)"
            )
            original = next(
                edge for edge in index["edges"]
                if edge.get("from") == getter["id"] and edge.get("kind") == "READS"
            )
            duplicate = dict(original)
            duplicate["id"] = "SYNTHETIC:DUPLICATE:READ"
            duplicate["source"] = {
                **original.get("source", {}),
                "line": int(original.get("source", {}).get("line", 1)) + 1,
            }
            index["edges"].append(duplicate)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = render_link(index, "Graph.getPosition(uint256)", detail="storage")
        finally:
            temporary.cleanup()

        rendered = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("Graph.positions  (2 direct)  [lexical]", rendered)
        self.assertEqual(rendered.count("Graph.positions"), 1)

    def test_ast_storage_context_edges_survive_scope_without_propagation_clones(self):
        temporary, root = self.fixture()
        try:
            index = self._index(root)
            nodes = {item["id"]: item for item in index["nodes"]}
            entry = next(item for item in nodes.values() if item.get("qualified_name") == "Graph.withdraw(uint256)")
            helper = next(item for item in nodes.values() if item.get("qualified_name") == "Graph._debit(address,uint256)")
            balance = next(item for item in nodes.values() if item.get("qualified_name") == "Graph.balances")
            positions = next(item for item in nodes.values() if item.get("qualified_name") == "Graph.positions")
            unrelated_entry = next(
                item for item in nodes.values()
                if item.get("qualified_name") == "ImportedMath.plus(uint256,uint256)"
            )
            index["edges"].extend([
                {
                    "id": "AST:storage:helper-context",
                    "kind": "WRITES",
                    "from": helper["id"],
                    "to": balance["id"],
                    "resolution": "INFERRED",
                    "evidence": "SOLC_AST_STORAGE_DECLARATION_REFERENCE",
                    "source": {"file": "src/Graph.sol", "line": 104, "column": 21},
                    "access_path": "balances[user]",
                    "operation": "assignment",
                    "persistence": "persistent",
                    "via": [entry["id"], helper["id"]],
                },
                {
                    "id": "PROPAGATED:storage:helper-context",
                    "kind": "WRITES",
                    "from": entry["id"],
                    "to": balance["id"],
                    "resolution": "INFERRED",
                    "evidence": "CALL_GRAPH_PROPAGATION",
                    "source": {"file": "src/Graph.sol", "line": 104, "column": 21},
                    "access_path": "balances[user]",
                    "operation": "assignment",
                    "persistence": "persistent",
                    "via": [entry["id"], helper["id"]],
                },
                {
                    "id": "AST:storage:unrelated-caller-context",
                    "kind": "WRITES",
                    "from": helper["id"],
                    "to": positions["id"],
                    "resolution": "INFERRED",
                    "evidence": "SOLC_AST_STORAGE_DECLARATION_REFERENCE",
                    "source": {"file": "src/Graph.sol", "line": 105, "column": 21},
                    "access_path": "positions[user]",
                    "operation": "assignment",
                    "persistence": "persistent",
                    "via": [unrelated_entry["id"], helper["id"]],
                },
            ])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = render_link(index, "Graph.withdraw(uint256)", detail="storage")
        finally:
            temporary.cleanup()

        rendered = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("Graph.balances  (2 via helpers)  [AST + lexical]", rendered)
        self.assertEqual(rendered.count("Graph.balances"), 2)  # one read group and one write group
        self.assertNotIn("Graph.positions", rendered)

    def test_function_summary_includes_reachable_helper_effects(self):
        temporary, root = self.fixture()
        try:
            index = self._index(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = render_link(index, "Graph.withdraw(uint256)")
        finally:
            temporary.cleanup()

        rendered = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("AT A GLANCE", rendered)
        self.assertIn("lastDebitAmount", rendered)
        self.assertIn("balances", rendered)
        self.assertIn("[helper]", rendered)
        self.assertNotIn("relationships=", rendered)
        self.assertNotIn("RESOLUTION ambiguous=", rendered)

    def test_link_help_documents_flags_use_cases_and_copy_paste_examples(self):
        help_text = _link_parser().format_help()

        for option in (
            "--root", "--depth", "--only", "--detail", "--limit",
            "--search", "--type", "--page", "--all", "--json",
            "-h", "--h", "--help",
        ):
            self.assertIn(option, help_text)

        for example in (
            "lk link --root ../protocol",
            "lk link --search Vault",
            "lk link --type interface",
            "lk link --page 2",
            "lk link --all",
            "lk link Vault --only writes",
            "lk link Vault --depth 3",
            "lk trace source Vault.increasePosition --detail storage",
            "lk link Vault --only writes --limit 60",
            "lk link ContractName.mappingName",
            "lk link --search Vault --json",
        ):
            self.assertIn(example, help_text)

        self.assertIn("Scan another project", help_text)
        self.assertIn("Use calls for caller/callee flow", help_text)
        self.assertIn("Increase it when a section reports omitted entries", help_text)
        self.assertIn("requires no TARGET", help_text)
        self.assertIn("Function default is 3", help_text)

    def test_link_help_uses_send_style_and_explains_every_option(self):
        for flag in ("--h", "--help", "-h", "help"):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["link", flag])
            rendered = output.getvalue()
            self.assertEqual(code, 0)
            for item in (
                "LOWKEY HELP  •  lk link",
                "What it does:",
                "When to use:",
                "Usage: lk link",
                "COMMAND VARIATIONS",
                "OPTIONS / MODES",
                "RELATED COMMANDS",
                "HELP TIP",
                "--root <DIR>",
                "--depth <N>",
                "--only <FILTER>",
                "--detail <VIEW>",
                "--limit <N>",
                "--search <TEXT>",
                "--type <KIND>",
                "--page <N>",
                "--all",
                "--json",
                "requires no TARGET",
                "do not prove execution",
            ):
                self.assertIn(item, rendered)

    def test_trace_source_help_explains_static_vs_runtime_trace(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["trace", "source", "--h"])
        rendered = output.getvalue()

        self.assertEqual(code, 0)
        self.assertIn("LOWKEY HELP  •  lk trace source", rendered)
        self.assertIn("source-level execution path", rendered)
        self.assertIn("not the same as 'lk trace <TX>'", rendered)
        self.assertIn("--detail <VIEW>", rendered)
        self.assertIn("--depth <N>", rendered)
        self.assertIn("--search <TEXT>", rendered)
        self.assertIn("--type <KIND>", rendered)
        self.assertIn("--page <N>", rendered)
        self.assertIn("--all", rendered)
        self.assertIn("When TARGET is omitted", rendered)
        self.assertIn("lk trace source 'PositionManager.increasePosition(uint256)'", rendered)

    def test_fn_asset_flow_help_explains_direction_asset_and_scope(self):
        for flag in ("--h", "--help", "-h", "help"):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = run_flow([flag])
            rendered = output.getvalue()

            self.assertEqual(code, 0)
            self.assertIn("LOWKEY HELP  •  lk fn --flow", rendered)
            self.assertIn("required direction", rendered)
            self.assertIn("--flow <in|out|both>", rendered)
            self.assertIn("--asset <eth|erc20|all>", rendered)
            self.assertIn("--root <DIR>", rendered)
            self.assertIn("--json", rendered)
            self.assertIn("separate from 'lk fn <filter>'", rendered)
            self.assertIn("does not prove that a transfer happened", rendered)

    def test_source_relationship_root_help_points_to_specific_menus(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--h"])
        rendered = output.getvalue()

        self.assertEqual(code, 0)
        self.assertIn("LOWKEY HELP  •  lk source relationships", rendered)
        self.assertIn("lk link --h", rendered)
        self.assertIn("lk trace source --h", rendered)
        self.assertIn("lk fn --flow --h", rendered)

    def test_flow_filter_separates_payable_capability_from_eth_out(self):
        temporary, root = self.fixture()
        try:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = run_flow(["--flow", "out", "--asset", "eth", "--root", str(root)])
        finally:
            temporary.cleanup()
        text = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("ETH", text)
        self.assertIn("OUT", text)
        self.assertIn("withdraw(uint256)", text)
        self.assertNotIn("deposit()", text)


if __name__ == "__main__":
    unittest.main()
