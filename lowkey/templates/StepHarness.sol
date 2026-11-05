// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Lowkey Step[] harness template.
/// @dev Calls are deliberately low-level and ordered. The one-shot reentry hook
///      is native-ETH-only. Token receiver callbacks require separate adapters.
///      The companion expectations JSON is declarative, not execution evidence.
contract {{CONTRACT_NAME}} {
    address private _lowkeyReenterTarget;
    bytes private _lowkeyReenterCalldata;
    bool private _lowkeyReenterEnabled;
    bool private _lowkeyReenterEntered;

    receive() external payable {
        if (_lowkeyReenterEnabled && !_lowkeyReenterEntered) {
            _lowkeyReenterEntered = true;
            (bool ok, bytes memory reason) =
                _lowkeyReenterTarget.call(_lowkeyReenterCalldata);
            if (!ok) assembly { revert(add(reason, 0x20), mload(reason)) }
        }
    }

    function run() external payable returns (bytes[] memory results) {
        _lowkeyReenterEnabled = false;
        _lowkeyReenterEntered = false;
        results = new bytes[]({{STEP_COUNT}});
{{STEP_BODY}}
    }
}
