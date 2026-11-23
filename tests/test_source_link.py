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
                status = main(["link", "--root", str(root)])
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

    def test_bare_link_supports_json_project_index(self):
        temporary, root = self.fixture()
        try:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["link", "--root", str(root), "--json"])
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
        self.assertIn("2 access(es)", rendered)
        self.assertEqual(rendered.count("Graph.positions"), 1)

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
        self.assertIn("via helpers", rendered)
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
