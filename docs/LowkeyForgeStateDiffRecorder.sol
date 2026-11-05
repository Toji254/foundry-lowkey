// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Lowkey Forge state-diff recorder.
// Inherit this helper from a Foundry test. Start recording directly before the
// target call and write the artifact immediately after that call.
import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";

abstract contract LowkeyForgeStateDiffRecorder is Test {
    address private _lowkeyTarget;
    bytes32 private _lowkeyTargetCodeHash;
    uint256 private _lowkeyChainId;
    uint256 private _lowkeyBlockNumber;
    bytes32 private _lowkeyParentHash;

    function _uintString(uint256 value) private pure returns (string memory) {
        if (value == 0) return "0";
        uint256 digits;
        uint256 cursor = value;
        while (cursor != 0) {
            ++digits;
            cursor /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            --digits;
            buffer[digits] = bytes1(uint8(48 + (value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    function _hex(bytes memory value) private pure returns (string memory) {
        bytes16 alphabet = "0123456789abcdef";
        bytes memory output = new bytes(2 + value.length * 2);
        output[0] = "0";
        output[1] = "x";
        for (uint256 i; i < value.length; ++i) {
            uint8 item = uint8(value[i]);
            output[2 + i * 2] = alphabet[item >> 4];
            output[3 + i * 2] = alphabet[item & 0x0f];
        }
        return string(output);
    }

    function _quoted(string memory value) private pure returns (string memory) {
        // Every caller passes a Lowkey-generated 0x-prefixed hex string.
        // It contains no quote or control characters and needs no escaping.
        return string.concat('"', value, '"');
    }

    function _boolean(bool value) private pure returns (string memory) {
        return value ? "true" : "false";
    }

    function _lowkeyStartTrace(address target) internal {
        _lowkeyTarget = target;
        _lowkeyTargetCodeHash = target.codehash;
        _lowkeyChainId = vm.getChainId();
        _lowkeyBlockNumber = vm.getBlockNumber();
        _lowkeyParentHash = block.number == 0 ? bytes32(0) : blockhash(block.number - 1);
        vm.startStateDiffRecording();
    }

    function _serializeStorageAccess(Vm.StorageAccess memory access)
        private
        pure
        returns (string memory json)
    {
        json = "{";
        json = string.concat(json, '"account":', _quoted(_hex(abi.encodePacked(access.account))));
        json = string.concat(json, ',"slot":', _quoted(_hex(abi.encodePacked(access.slot))));
        json = string.concat(json, ',"is_write":', _boolean(access.isWrite));
        json = string.concat(json, ',"previous_value":', _quoted(_hex(abi.encodePacked(access.previousValue))));
        json = string.concat(json, ',"new_value":', _quoted(_hex(abi.encodePacked(access.newValue))));
        json = string.concat(json, ',"reverted":', _boolean(access.reverted), "}");
    }

    function _serializeStorageAccesses(Vm.StorageAccess[] memory accesses)
        private
        pure
        returns (string memory json)
    {
        json = "[";
        for (uint256 i; i < accesses.length; ++i) {
            if (i != 0) json = string.concat(json, ",");
            json = string.concat(json, _serializeStorageAccess(accesses[i]));
        }
        json = string.concat(json, "]");
    }

    function _serializeAccountAccess(Vm.AccountAccess memory access)
        private
        pure
        returns (string memory json)
    {
        json = "{";
        json = string.concat(json, '"kind":', _uintString(uint256(access.kind)));
        json = string.concat(json, ',"account":', _quoted(_hex(abi.encodePacked(access.account))));
        json = string.concat(json, ',"accessor":', _quoted(_hex(abi.encodePacked(access.accessor))));
        json = string.concat(json, ',"initialized":', _boolean(access.initialized));
        json = string.concat(json, ',"old_balance":', _uintString(access.oldBalance));
        json = string.concat(json, ',"new_balance":', _uintString(access.newBalance));
        json = string.concat(json, ',"deployed_code":', _quoted(_hex(access.deployedCode)));
        json = string.concat(json, ',"value":', _uintString(access.value));
        json = string.concat(json, ',"data":', _quoted(_hex(access.data)));
        json = string.concat(json, ',"depth":', _uintString(access.depth));
        json = string.concat(json, ',"old_nonce":', _uintString(access.oldNonce));
        json = string.concat(json, ',"new_nonce":', _uintString(access.newNonce));
        json = string.concat(json, ',"code_hash":', _quoted(_hex(abi.encodePacked(access.account.codehash))));
        json = string.concat(json, ',"chain_id":', _uintString(access.chainInfo.chainId));
        json = string.concat(json, ',"reverted":', _boolean(access.reverted));
        json = string.concat(json, ',"storage_accesses":', _serializeStorageAccesses(access.storageAccesses));
        json = string.concat(json, "}");
    }

    function _lowkeyWriteTrace(string memory outputPath) internal {
        address target = _lowkeyTarget;
        Vm.AccountAccess[] memory accesses = vm.stopAndReturnStateDiff();
        string memory accessesJson = "[";
        for (uint256 i; i < accesses.length; ++i) {
            if (i != 0) accessesJson = string.concat(accessesJson, ",");
            accessesJson = string.concat(accessesJson, _serializeAccountAccess(accesses[i]));
        }
        accessesJson = string.concat(accessesJson, "]");

        string memory finalJson = '{"backend":"forge-state-diff","schema_version":1';
        finalJson = string.concat(finalJson, ',"chain_id":', _uintString(_lowkeyChainId));
        finalJson = string.concat(finalJson, ',"block_number":', _uintString(_lowkeyBlockNumber));
        finalJson = string.concat(finalJson, ',"target_address":', _quoted(_hex(abi.encodePacked(target))));
        finalJson = string.concat(finalJson, ',"target_code_hash":', _quoted(_hex(abi.encodePacked(_lowkeyTargetCodeHash))));
        finalJson = string.concat(finalJson, ',"fork_parent_hash":', _quoted(_hex(abi.encodePacked(_lowkeyParentHash))));
        finalJson = string.concat(finalJson, ',"accesses":', accessesJson, "}");

        vm.createDir(".audit/godmode", true);
        vm.writeJson(finalJson, outputPath);
    }
}
