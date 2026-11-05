// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Lowkey Step[] harness template.
/// @dev Calls are deliberately low-level and ordered. Reverts, return bytes and
///      nested call paths must be inspected from the selected execution backend.
///      The companion expectations JSON is declarative and is not proof.
contract {{CONTRACT_NAME}} {
    receive() external payable {}

    function run() external payable returns (bytes[] memory results) {
        results = new bytes[]({{STEP_COUNT}});
{{STEP_BODY}}
    }
}
