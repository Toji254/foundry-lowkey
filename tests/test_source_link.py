import contextlib
import importlib.util
import io
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
if str(LOWKEY) not in sys.path:
    sys.path.insert(0, str(LOWKEY))

from source_index import build_source_index
from source_link import render_link, run_flow


class SourceLinkTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(temporary.name)
        (root / "src").mkdir()
        (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")
        (root / "src" / "BaseLink.sol").write_text(
            """
            pragma solidity ^0.8.20;
            abstract contract BaseLink {
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
            contract Graph is BaseLink {
                using LinkLib for uint256;
                mapping(address => uint256) public balances;
                event Paid(address indexed user, uint256 amount);
                function deposit() external payable {
                    balances[msg.sender] += msg.value;
                }
                function baseAction() public override {}
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
                    balances[user] -= amount;
                }
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
                status = render_link(index, "Graph.withdraw(uint256)")
        finally:
            temporary.cleanup()
        text = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("LOWKEY // SOURCE LINK", text)
        self.assertIn("CALLS", text)
        self.assertIn("_debit(address,uint256)", text)
        self.assertIn("STORAGE WRITES", text)
        self.assertIn("ASSET FLOW / CAPABILITY", text)

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
        self.assertIn("MAPPING KEYS", text)
        self.assertIn("address", text)
        self.assertIn("MAPPING VALUE TYPE", text)
        self.assertIn("READ BY", text)
        self.assertIn("WRITTEN BY", text)
        self.assertIn("balances[who]", text)

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
        self.assertIn("INTERNAL CALLS", text)

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
