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

    function _lowkeyWriteTrace(string memory outputPath) internal {
        address target = _lowkeyTarget;
        Vm.AccountAccess[] memory accesses = vm.stopAndReturnStateDiff();
        string memory accessesJson = "[";

        for (uint256 i; i < accesses.length; ++i) {
            Vm.AccountAccess memory access = accesses[i];
            string memory storageJson = "[";

            for (uint256 j; j < access.storageAccesses.length; ++j) {
                Vm.StorageAccess memory storageAccess = access.storageAccesses[j];
                string memory storageObject = string.concat(
                    '{"account":', _quoted(_hex(abi.encodePacked(storageAccess.account))),
                    ',"slot":', _quoted(_hex(abi.encodePacked(storageAccess.slot))),
                    ',"is_write":', _boolean(storageAccess.isWrite),
                    ',"previous_value":', _quoted(_hex(abi.encodePacked(storageAccess.previousValue))),
                    ',"new_value":', _quoted(_hex(abi.encodePacked(storageAccess.newValue))),
                    ',"reverted":', _boolean(storageAccess.reverted),
                    '}'
                );
                if (j != 0) storageJson = string.concat(storageJson, ",");
                storageJson = string.concat(storageJson, storageObject);
            }
            storageJson = string.concat(storageJson, "]");

            string memory accessObject = string.concat(
                '{"kind":', _uintString(uint256(access.kind)),
                ',"account":', _quoted(_hex(abi.encodePacked(access.account))),
                ',"accessor":', _quoted(_hex(abi.encodePacked(access.accessor))),
                ',"initialized":', _boolean(access.initialized),
                ',"old_balance":', _uintString(access.oldBalance),
                ',"new_balance":', _uintString(access.newBalance),
                ',"deployed_code":', _quoted(_hex(access.deployedCode)),
                ',"value":', _uintString(access.value),
                ',"data":', _quoted(_hex(access.data)),
                ',"depth":', _uintString(access.depth),
                ',"old_nonce":', _uintString(access.oldNonce),
                ',"new_nonce":', _uintString(access.newNonce),
                ',"code_hash":', _quoted(_hex(abi.encodePacked(access.account.codehash))),
                ',"chain_id":', _uintString(access.chainInfo.chainId),
                ',"reverted":', _boolean(access.reverted),
                ',"storage_accesses":', storageJson,
                '}'
            );
            if (i != 0) accessesJson = string.concat(accessesJson, ",");
            accessesJson = string.concat(accessesJson, accessObject);
        }
        accessesJson = string.concat(accessesJson, "]");

        string memory finalJson = string.concat(
            '{"backend":"forge-state-diff"',
            ',"schema_version":1',
            ',"chain_id":', _uintString(_lowkeyChainId),
            ',"block_number":', _uintString(_lowkeyBlockNumber),
            ',"target_address":', _quoted(_hex(abi.encodePacked(target))),
            ',"target_code_hash":', _quoted(_hex(abi.encodePacked(_lowkeyTargetCodeHash))),
            ',"fork_parent_hash":', _quoted(_hex(abi.encodePacked(_lowkeyParentHash))),
            ',"accesses":', accessesJson,
            '}'
        );

        vm.createDir(".audit/godmode", true);
        vm.writeJson(finalJson, outputPath);
    }
}
