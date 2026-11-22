import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
if str(LOWKEY) not in sys.path:
    sys.path.insert(0, str(LOWKEY))

from source_index import build_source_index, find_symbols


class SourceIndexTests(unittest.TestCase):
    def write(self, root: pathlib.Path, relative: str, content: str) -> pathlib.Path:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(temporary.name)
        self.write(root, "foundry.toml", '[profile.default]\nsrc = "src"\n')
        self.write(
            root,
            "src/IERC20.sol",
            """
            pragma solidity ^0.8.20;
            interface IERC20 {
                function transfer(address to, uint256 amount) external returns (bool);
                function transferFrom(address from, address to, uint256 amount) external returns (bool);
            }
            """,
        )
        self.write(
            root,
            "src/SafeERC20.sol",
            """
            pragma solidity ^0.8.20;
            import "./IERC20.sol";
            library SafeERC20 {
                function safeTransfer(IERC20 token, address to, uint256 amount) internal {
                    token.transfer(to, amount);
                }
            }
            """,
        )
        self.write(
            root,
            "src/BaseVault.sol",
            """
            pragma solidity ^0.8.20;
            abstract contract BaseVault {
                address internal owner;
                modifier onlyOwner() { require(msg.sender == owner); _; }
                function health() internal virtual returns (uint256) { return 1; }
            }
            """,
        )
        self.write(
            root,
            "src/Vault.sol",
            """
            pragma solidity ^0.8.20;
            import "./IERC20.sol";
            import "./BaseVault.sol";
            import "./SafeERC20.sol";

            contract Vault is BaseVault {
                using SafeERC20 for IERC20;
                enum Status { Open, Closed }
                struct Position {
                    address owner;
                    uint256 debt;
                }

                mapping(address => mapping(uint256 => Position)) public positions;
                IERC20 public token;
                uint256 public totalDeposits = 1;
                address payable public treasury;
                uint256 internal guard;
                uint256[] public amounts;
                function(uint256) external callback;

                event Deposited(address indexed who, uint256 amount);
                event Withdrawn(address indexed who, uint256 amount);
                error Unauthorized(address caller);
                modifier nonReentrant() { guard += 1; _; }

                function health() internal override returns (uint256) { return 2; }

                function setOwner(address next) external onlyOwner {
                    owner = next;
                }

                function deposit() external payable {
                    positions[msg.sender][1].debt += msg.value;
                    emit Deposited(msg.sender, msg.value);
                }

                function withdraw(uint256 amount) external onlyOwner nonReentrant {
                    _update(msg.sender, amount);
                    token.safeTransfer(msg.sender, amount);
                    (bool ok,) = msg.sender.call{value: amount}("");
                    require(ok);
                    emit Withdrawn(msg.sender, amount);
                }

                function _update(address user, uint256 amount) internal {
                    positions[user][1].debt -= amount;
                }

                function _updateViaAlias(address user, uint256 amount) internal {
                    Position storage p = positions[user][1];
                    p.debt += amount;
                }

                function getPosition(address user) external view returns (uint256) {
                    return positions[user][1].debt;
                }

                function transferDirect(address to, uint256 amount) external {
                    token.transfer(to, amount);
                }

                function externalTransferFrom(address from, address to, uint256 amount) external {
                    token.transferFrom(from, to, amount);
                }

                function pullTokenIn(address from, uint256 amount) external {
                    token.transferFrom(from, address(this), amount);
                }

                function sendNative(uint256 amount) external {
                    treasury.transfer(amount);
                }

                function revertWithCustomError() external {
                    revert Unauthorized(msg.sender);
                }

                function typeCast(uint256 value) external pure returns (uint256) {
                    return uint256(value);
                }

                function invokeCallback(function(uint256) external cb, uint256 value) external {
                    cb(value);
                }

                function invokeStoredCallback(uint256 value) external {
                    callback(value);
                }

                function setCallback(function(uint256) external cb) external {
                    callback = cb;
                }

                function updateArray(uint256 value) external {
                    amounts.push(value);
                }

                function removeArrayItem() external {
                    amounts.pop();
                }

                function rawStorageWrite() external {
                    assembly {
                        sstore(0, 1)
                    }
                }

                function overloaded(uint256 value) internal pure returns (uint256) {
                    return value;
                }

                function overloaded(address value) internal pure returns (address) {
                    return value;
                }

                function testOverload() external {
                    overloaded(uint256(1));
                }

                function commentedOnly() external view {
                    // fakeCall(); positions[msg.sender][1] = Position(msg.sender, 1);
                }

                function localShadow() external pure returns (uint256) {
                    uint256 positions = 7;
                    return positions;
                }

                function abiEncoding(address who) external pure returns (bytes memory) {
                    return abi.encode(who);
                }
            }
            """,
        )
        return temporary, root

    def test_indexes_contract_functions_mapping_and_struct_fields(self):
        temporary, root = self.fixture()
        try:
            index = build_source_index(root, use_cache=False)
        finally:
            temporary.cleanup()

        self.assertEqual(index["parser"], "LEXICAL")
        self.assertEqual(index["summary"]["contracts"], 4)
        self.assertTrue(find_symbols(index, "Vault"))
        self.assertEqual(
            len(find_symbols(index, "Vault.withdraw(uint256)")),
            1,
        )
        mapping = find_symbols(index, "Vault.positions")
        self.assertEqual(len(mapping), 1)
        self.assertEqual(mapping[0]["kind"], "mapping")
        self.assertIn("mapping(uint256 => Position)", mapping[0]["type"])
        self.assertEqual(mapping[0]["mapping_keys"], ["address", "uint256"])
        self.assertEqual(mapping[0]["mapping_value_type"], "Position")
        self.assertIsNone(mapping[0].get("initializer"))
        self.assertFalse(any(edge["kind"] == "INITIALIZES" and edge["to"] == mapping[0]["id"] for edge in index["edges"]))
        total_deposits = next(item for item in index["nodes"] if item.get("qualified_name") == "Vault.totalDeposits")
        self.assertEqual(total_deposits.get("initializer"), "1")
        self.assertTrue(any(edge["kind"] == "INITIALIZES" and edge["to"] == total_deposits["id"] for edge in index["edges"]))
        self.assertTrue(find_symbols(index, "Vault.Position.debt"))
        self.assertTrue(find_symbols(index, "Vault.Status"))
        self.assertTrue(find_symbols(index, "Vault.Status.Open"))

    def test_direct_calls_storage_access_modifiers_and_events_are_linked(self):
        temporary, root = self.fixture()
        try:
            index = build_source_index(root, use_cache=False)
        finally:
            temporary.cleanup()

        nodes = {item["id"]: item for item in index["nodes"]}
        functions = {item.get("qualified_name"): item["id"] for item in index["nodes"] if item.get("kind") == "function"}
        withdraw_id = functions["Vault.withdraw(uint256)"]
        update_id = functions["Vault._update(address,uint256)"]
        edges = index["edges"]

        self.assertTrue(any(edge["kind"] == "CALLS" and edge["from"] == withdraw_id and edge["to"] == update_id for edge in edges))
        library_functions = [item for item in index["nodes"] if item.get("qualified_name") == "SafeERC20.safeTransfer(IERC20,address,uint256)"]
        self.assertEqual(len(library_functions), 1)
        self.assertTrue(any(edge["kind"] == "CALLS" and edge["from"] == withdraw_id and edge["to"] == library_functions[0]["id"] and edge.get("call_kind") == "using-for extension" for edge in edges))
        direct_transfer = next(item for item in index["nodes"] if item.get("qualified_name") == "Vault.transferDirect(address,uint256)")
        interface_transfer = next(item for item in index["nodes"] if item.get("qualified_name") == "IERC20.transfer(address,uint256)")
        external_edge = next(edge for edge in edges if edge["kind"] == "EXTERNAL_CALL" and edge["from"] == direct_transfer["id"] and edge["to"] == interface_transfer["id"])
        self.assertEqual(external_edge["resolution"], "DIRECT")
        self.assertEqual(external_edge["implementation_resolution"], "UNRESOLVED")
        self.assertTrue(any(edge["kind"] == "APPLIES_MODIFIER" and edge["from"] == withdraw_id for edge in edges))
        guard_state = next(item for item in index["nodes"] if item.get("qualified_name") == "Vault.guard")
        self.assertTrue(any(edge["kind"] == "WRITES" and edge["to"] == guard_state["id"] and edge["resolution"] == "DIRECT" for edge in edges if nodes.get(edge["from"], {}).get("kind") == "modifier"))
        self.assertTrue(any(edge["kind"] == "WRITES" and edge["from"] == withdraw_id and edge["to"] == guard_state["id"] and edge["resolution"] == "INFERRED" for edge in edges))
        self.assertTrue(any(edge["kind"] == "APPLIES_MODIFIER" and edge["from"] == withdraw_id and edge["resolution"] == "INFERRED" for edge in edges if nodes.get(edge["to"], {}).get("name") == "onlyOwner"))
        owner_setter = next(item for item in index["nodes"] if item.get("qualified_name") == "Vault.setOwner(address)")
        owner_state = next(item for item in index["nodes"] if item.get("qualified_name") == "BaseVault.owner")
        self.assertTrue(any(edge["kind"] == "WRITES" and edge["from"] == owner_setter["id"] and edge["to"] == owner_state["id"] and edge["resolution"] == "INFERRED" for edge in edges))
        health_override = next(item for item in index["nodes"] if item.get("qualified_name") == "Vault.health()")
        base_health = next(item for item in index["nodes"] if item.get("qualified_name") == "BaseVault.health()")
        self.assertTrue(any(edge["kind"] == "OVERRIDES" and edge["from"] == health_override["id"] and edge["to"] == base_health["id"] for edge in edges))
        self.assertTrue(any(edge["kind"] == "EMITS" and edge["from"] == withdraw_id for edge in edges))
        self.assertTrue(any(edge["kind"] == "WRITES" and edge["from"] == update_id for edge in edges))
        self.assertFalse(any(edge["kind"] == "CALLS" and edge.get("to") == "function-name:Vault.Deposited" for edge in edges))
        revert_func = next(item for item in index["nodes"] if item.get("qualified_name") == "Vault.revertWithCustomError()")
        custom_error = next(item for item in index["nodes"] if item.get("qualified_name") == "Vault.Unauthorized")
        self.assertTrue(any(edge["kind"] == "REVERTS" and edge["from"] == revert_func["id"] and edge["to"] == custom_error["id"] for edge in edges))
        cast_func = next(item for item in index["nodes"] if item.get("qualified_name") == "Vault.typeCast(uint256)")
        self.assertFalse(any(edge["kind"] == "CALLS" and edge["from"] == cast_func["id"] and edge.get("to") == "function-name:Vault.uint256" for edge in edges))
        debt_field = next(item for item in index["nodes"] if item.get("qualified_name") == "Vault.Position.debt")
        self.assertTrue(any(edge["kind"] == "WRITES" and edge["from"] == update_id and edge["to"] == debt_field["id"] for edge in edges))
        alias_function = next(item for item in index["nodes"] if item.get("qualified_name") == "Vault._updateViaAlias(address,uint256)")
        positions_node = mapping[0]
        self.assertTrue(any(edge["kind"] == "ALIASES_STORAGE" and edge["from"] == alias_function["id"] and edge["to"] == positions_node["id"] and edge.get("alias") == "p" and edge.get("keys") == ["user", "1"] for edge in edges))
        self.assertTrue(any(edge["kind"] == "WRITES" and edge["from"] == alias_function["id"] and edge["to"] == debt_field["id"] and edge.get("alias") == "p" for edge in edges))
        self.assertTrue(any(edge["kind"] == "READS" and nodes.get(edge["from"], {}).get("name") == "getPosition" for edge in edges))
        self.assertTrue(any(edge["kind"] == "WRITES" and edge["from"] == withdraw_id and edge["resolution"] == "INFERRED" for edge in edges))

    def test_flow_distinguishes_payable_capability_from_transfer_attempts(self):
        temporary, root = self.fixture()
        try:
            index = build_source_index(root, use_cache=False)
        finally:
            temporary.cleanup()

        nodes = {item["id"]: item for item in index["nodes"]}
        flow_edges = [edge for edge in index["edges"] if edge["kind"] == "ASSET_FLOW"]
        deposit = next(item for item in nodes.values() if item.get("qualified_name") == "Vault.deposit()")
        withdraw = next(item for item in nodes.values() if item.get("qualified_name") == "Vault.withdraw(uint256)")

        self.assertTrue(any(edge["from"] == deposit["id"] and edge["asset"] == "eth" and edge["direction"] == "in" and edge["status"] == "CAPABILITY" for edge in flow_edges))
        self.assertTrue(any(edge["from"] == withdraw["id"] and edge["asset"] == "eth" and edge["direction"] == "out" and edge["status"] == "TRANSFER_ATTEMPT" for edge in flow_edges))
        self.assertTrue(any(edge["from"] == withdraw["id"] and edge["asset"] == "erc20" and edge["direction"] == "out" for edge in flow_edges))
        direct_transfer = next(item for item in nodes.values() if item.get("qualified_name") == "Vault.transferDirect(address,uint256)")
        external_pull = next(item for item in nodes.values() if item.get("qualified_name") == "Vault.externalTransferFrom(address,address,uint256)")
        inbound_pull = next(item for item in nodes.values() if item.get("qualified_name") == "Vault.pullTokenIn(address,uint256)")
        native_send = next(item for item in nodes.values() if item.get("qualified_name") == "Vault.sendNative(uint256)")
        self.assertTrue(any(edge["from"] == external_pull["id"] and edge["asset"] == "erc20" and edge["direction"] == "unresolved" for edge in flow_edges))
        self.assertTrue(any(edge["from"] == inbound_pull["id"] and edge["asset"] == "erc20" and edge["direction"] == "in" for edge in flow_edges))
        self.assertFalse(any(edge["from"] == direct_transfer["id"] and edge["asset"] == "eth" for edge in flow_edges))
        self.assertTrue(any(edge["from"] == native_send["id"] and edge["asset"] == "eth" and edge["direction"] == "out" for edge in flow_edges))
        self.assertFalse(any(edge["kind"] == "EXTERNAL_CALL" and edge["from"] == native_send["id"] and edge.get("method") == "transfer" for edge in index["edges"]))

    def test_overloads_are_reported_as_ambiguous_without_a_signature(self):
        temporary, root = self.fixture()
        try:
            index = build_source_index(root, use_cache=False)
        finally:
            temporary.cleanup()

        self.assertEqual(len(find_symbols(index, "Vault.overloaded")), 2)
        self.assertEqual(len(find_symbols(index, "Vault.overloaded(uint256)")), 1)

    def test_dynamic_function_pointers_and_assembly_storage_are_unresolved(self):
        temporary, root = self.fixture()
        try:
            index = build_source_index(root, use_cache=False)
        finally:
            temporary.cleanup()

        invoke = next(item for item in index["nodes"] if item.get("qualified_name") == "Vault.invokeCallback(function,uint256)")
        stored = next(item for item in index["nodes"] if item.get("qualified_name") == "Vault.invokeStoredCallback(uint256)")
        self.assertFalse(any(item.get("qualified_name") == "Vault.fallback(uint256)" for item in index["nodes"]))
        edges = index["edges"]
        self.assertTrue(any(edge["kind"] == "CALLS" and edge["from"] == invoke["id"] and edge["resolution"] == "UNRESOLVED" and edge.get("call_kind") == "dynamic-function-pointer" for edge in edges))
        self.assertTrue(any(edge["kind"] == "CALLS" and edge["from"] == stored["id"] and edge["resolution"] == "UNRESOLVED" and edge.get("call_kind") == "dynamic-function-pointer" for edge in edges))
        self.assertTrue(any(edge["kind"] == "UNRESOLVED_STORAGE" and edge.get("operation") == "sstore" for edge in edges))
        callback_node = next(item for item in index["nodes"] if item.get("qualified_name") == "Vault.callback")
        self.assertTrue(any(edge["kind"] == "READS" and edge["to"] == callback_node["id"] and edge["from"] == stored["id"] for edge in edges))
        setter = next(item for item in index["nodes"] if item.get("qualified_name") == "Vault.setCallback(function)")
        self.assertTrue(any(edge["kind"] == "WRITES" and edge["to"] == callback_node["id"] and edge["from"] == setter["id"] for edge in edges))
        amounts = next(item for item in index["nodes"] if item.get("qualified_name") == "Vault.amounts")
        update_array = next(item for item in index["nodes"] if item.get("qualified_name") == "Vault.updateArray(uint256)")
        remove_array = next(item for item in index["nodes"] if item.get("qualified_name") == "Vault.removeArrayItem()")
        self.assertTrue(any(edge["kind"] == "WRITES" and edge["to"] == amounts["id"] and edge["from"] == update_array["id"] for edge in edges))
        self.assertTrue(any(edge["kind"] == "WRITES" and edge["to"] == amounts["id"] and edge["from"] == remove_array["id"] for edge in edges))

    def test_comments_do_not_create_call_or_storage_edges(self):
        temporary, root = self.fixture()
        try:
            index = build_source_index(root, use_cache=False)
        finally:
            temporary.cleanup()

        function = find_symbols(index, "Vault.commentedOnly")[0]
        edges = [edge for edge in index["edges"] if edge["from"] == function["id"]]
        self.assertFalse(any(edge["kind"] == "CALLS" and "fakeCall" in edge.get("to", "") for edge in edges))
        self.assertFalse(any(edge["kind"] in {"READS", "WRITES"} and "positions" in edge.get("variable", "") for edge in edges))

    def test_local_shadow_and_abi_intrinsics_do_not_create_false_edges(self):
        temporary, root = self.fixture()
        try:
            index = build_source_index(root, use_cache=False)
        finally:
            temporary.cleanup()

        mapping = find_symbols(index, "Vault.positions")[0]
        local_shadow = find_symbols(index, "Vault.localShadow()")[0]
        abi_encoding = find_symbols(index, "Vault.abiEncoding(address)")[0]
        self.assertFalse(any(edge["from"] == local_shadow["id"] and edge["to"] == mapping["id"] and edge["kind"] in {"READS", "WRITES"} for edge in index["edges"]))
        self.assertFalse(any(edge["from"] == abi_encoding["id"] and edge["kind"] == "EXTERNAL_CALL" and edge.get("receiver") == "abi" for edge in index["edges"]))

    def test_repeated_queries_use_the_content_addressed_cache(self):
        temporary, root = self.fixture()
        try:
            build_source_index(root)
            second = build_source_index(root)
        finally:
            temporary.cleanup()
        self.assertEqual(second["cache"]["status"], "HIT")


if __name__ == "__main__":
    unittest.main()
