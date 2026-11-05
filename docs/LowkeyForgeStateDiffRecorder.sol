// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Lowkey Forge state-diff recorder.
// Import this helper from a Foundry test which inherits forge-std/Test.sol.
// Start recording immediately before the exact call under investigation and
// write the artifact immediately after that call.
import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";

interface ILowkeyJson {
    function serializeString(string calldata objectKey, string calldata valueKey, string calldata value)
        external returns (string memory json);
    function serializeUint(string calldata objectKey, string calldata valueKey, uint256 value)
        external returns (string memory json);
    function serializeAddress(string calldata objectKey, string calldata valueKey, address value)
        external returns (string memory json);
    function serializeBool(string calldata objectKey, string calldata valueKey, bool value)
        external returns (string memory json);
    function serializeBytes(string calldata objectKey, string calldata valueKey, bytes calldata value)
        external returns (string memory json);
    function serializeBytes32(string calldata objectKey, string calldata valueKey, bytes32 value)
        external returns (string memory json);
    function writeJson(string calldata json, string calldata path) external;
}

abstract contract LowkeyForgeStateDiffRecorder is Test {
    ILowkeyJson internal constant lowkeyJson =
        ILowkeyJson(address(uint160(uint256(keccak256("hevm cheat code")))));
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
                string memory storageKey = string(
                    abi.encodePacked("lowkey.storage.", _uintString(i), ".", _uintString(j))
                );

                lowkeyJson.serializeAddress(storageKey, "account", storageAccess.account);
                lowkeyJson.serializeBytes32(storageKey, "slot", storageAccess.slot);
                lowkeyJson.serializeBool(storageKey, "is_write", storageAccess.isWrite);
                lowkeyJson.serializeBytes32(storageKey, "previous_value", storageAccess.previousValue);
                lowkeyJson.serializeBytes32(storageKey, "new_value", storageAccess.newValue);
                string memory storageObject =
                    lowkeyJson.serializeBool(storageKey, "reverted", storageAccess.reverted);

                if (j != 0) storageJson = string.concat(storageJson, ",");
                storageJson = string.concat(storageJson, storageObject);
            }
            storageJson = string.concat(storageJson, "]");

            string memory accessKey = string(
                abi.encodePacked("lowkey.access.", _uintString(i))
            );
            lowkeyJson.serializeUint(accessKey, "kind", uint256(access.kind));
            lowkeyJson.serializeAddress(accessKey, "account", access.account);
            lowkeyJson.serializeAddress(accessKey, "accessor", access.accessor);
            lowkeyJson.serializeBool(accessKey, "initialized", access.initialized);
            lowkeyJson.serializeUint(accessKey, "old_balance", access.oldBalance);
            lowkeyJson.serializeUint(accessKey, "new_balance", access.newBalance);
            lowkeyJson.serializeBytes(accessKey, "deployed_code", access.deployedCode);
            lowkeyJson.serializeUint(accessKey, "value", access.value);
            lowkeyJson.serializeBytes(accessKey, "data", access.data);
            lowkeyJson.serializeUint(accessKey, "depth", access.depth);
            lowkeyJson.serializeUint(accessKey, "old_nonce", access.oldNonce);
            lowkeyJson.serializeUint(accessKey, "new_nonce", access.newNonce);
            lowkeyJson.serializeBytes32(accessKey, "code_hash", access.account.codehash);
            lowkeyJson.serializeUint(accessKey, "chain_id", access.chainInfo.chainId);

            string memory accessObject =
                lowkeyJson.serializeBool(accessKey, "reverted", access.reverted);
            // serializeString detects valid JSON and embeds the array as JSON,
            // not as a quoted string.
            accessObject = lowkeyJson.serializeString(accessKey, "storage_accesses", storageJson);

            if (i != 0) accessesJson = string.concat(accessesJson, ",");
            accessesJson = string.concat(accessesJson, accessObject);
        }
        accessesJson = string.concat(accessesJson, "]");

        string memory rootKey = "lowkey.root";
        lowkeyJson.serializeString(rootKey, "backend", "forge-state-diff");
        lowkeyJson.serializeUint(rootKey, "schema_version", 1);
        lowkeyJson.serializeUint(rootKey, "chain_id", _lowkeyChainId);
        lowkeyJson.serializeUint(rootKey, "block_number", _lowkeyBlockNumber);
        lowkeyJson.serializeAddress(rootKey, "target_address", target);
        lowkeyJson.serializeBytes32(rootKey, "target_code_hash", _lowkeyTargetCodeHash);
        lowkeyJson.serializeBytes32(rootKey, "fork_parent_hash", _lowkeyParentHash);
        string memory finalJson = lowkeyJson.serializeString(rootKey, "accesses", accessesJson);

        vm.createDir(".audit/godmode", true);
        lowkeyJson.writeJson(finalJson, outputPath);
    }
}
