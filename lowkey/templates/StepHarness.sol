// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Lowkey Step[] harness template.
/// @dev The harness emits transactions only when run() is explicitly called.
///      Nested execution evidence must be obtained from the selected trace backend;
///      _stepCallCount records only calls emitted by this generated harness.
contract {{CONTRACT_NAME}} {
    uint256 private _stepCallCount;
    bool private _lastCallReverted;
    bytes private _lastReturnData;

    receive() external payable {}

    function run() external payable returns (bytes[] memory results) {
        results = new bytes[]({{STEP_COUNT}});
{{STEP_BODY}}
        _lastReturnData;
    }
}
