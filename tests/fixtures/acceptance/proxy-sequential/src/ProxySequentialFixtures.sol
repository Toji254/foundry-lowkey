// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILowkeyTransparentUpgrade {
    function upgradeToAndCall(address implementation, bytes calldata data) external payable;
}

abstract contract LowkeyUUPSStorage {
    bytes32 internal constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function _install(address nextImplementation) internal {
        require(nextImplementation.code.length > 0, "NO_IMPLEMENTATION_CODE");
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { sstore(slot, nextImplementation) }
    }

    function proxiableUUID() external pure returns (bytes32) { return IMPLEMENTATION_SLOT; }
}

contract VulnerableUUPSImplementation is LowkeyUUPSStorage {
    address public owner;
    function upgradeTo(address nextImplementation) external { _install(nextImplementation); }
}

contract SecureUUPSImplementation is LowkeyUUPSStorage {
    address public owner;
    function upgradeTo(address nextImplementation) external {
        require(msg.sender == owner, "ONLY_OWNER");
        _install(nextImplementation);
    }
}

contract LowkeyUUPSProxy {
    address public owner;
    bytes32 private constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    event Upgraded(address indexed implementation);

    constructor(address implementation_) {
        require(implementation_.code.length > 0, "NO_IMPLEMENTATION_CODE");
        owner = msg.sender;
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { sstore(slot, implementation_) }
        emit Upgraded(implementation_);
    }

    function implementation() external view returns (address value) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { value := sload(slot) }
    }

    // Fixture-only, owner-gated setup selector for paired scenario preparation.
    function setImplementationForLab(address nextImplementation) external {
        require(msg.sender == owner, "ONLY_OWNER");
        require(nextImplementation.code.length > 0, "NO_IMPLEMENTATION_CODE");
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { sstore(slot, nextImplementation) }
        emit Upgraded(nextImplementation);
    }

    fallback() external payable { _delegate(); }
    receive() external payable { _delegate(); }

    function _delegate() internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            let implementation_ := sload(slot)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), implementation_, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

contract LowkeyProxyReplacement is LowkeyUUPSStorage {
    function lowkeyProxyMarker() external pure returns (bytes32) {
        return keccak256("LOWKEY_PROXY_SEQUENTIAL_REPLACEMENT");
    }
}

contract PairedProxyAdmin {
    address private immutable _owner;
    bool public secureMode;

    constructor(address initialOwner) {
        require(initialOwner != address(0), "ZERO_OWNER");
        _owner = initialOwner;
    }

    function owner() external view returns (address) { return _owner; }
    function UPGRADE_INTERFACE_VERSION() external pure returns (string memory) { return "5.0.0"; }

    function setSecureMode(bool enabled) external {
        require(msg.sender == _owner, "ONLY_OWNER");
        secureMode = enabled;
    }

    function upgradeAndCall(address proxy, address implementation, bytes calldata data)
        external payable
    {
        if (secureMode) require(msg.sender == _owner, "ONLY_PROXY_ADMIN_OWNER");
        ILowkeyTransparentUpgrade(proxy).upgradeToAndCall{value: msg.value}(implementation, data);
    }
}

contract LowkeyTransparentProxy {
    address private immutable _admin;
    bytes32 private constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes4 private constant UPGRADE_TO_AND_CALL =
        bytes4(keccak256("upgradeToAndCall(address,bytes)"));
    event Upgraded(address indexed implementation);

    constructor(address implementation_, address admin_) {
        require(implementation_.code.length > 0, "NO_IMPLEMENTATION_CODE");
        require(admin_.code.length > 0, "NO_ADMIN_CODE");
        _admin = admin_;
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { sstore(slot, implementation_) }
        emit Upgraded(implementation_);
    }

    function implementation() external view returns (address value) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { value := sload(slot) }
    }

    fallback() external payable {
        if (msg.sender == _admin) {
            require(msg.sig == UPGRADE_TO_AND_CALL, "ADMIN_SELECTOR_ONLY");
            (address nextImplementation, bytes memory data) =
                abi.decode(msg.data[4:], (address, bytes));
            require(nextImplementation.code.length > 0, "NO_IMPLEMENTATION_CODE");
            bytes32 slot = IMPLEMENTATION_SLOT;
            assembly { sstore(slot, nextImplementation) }
            emit Upgraded(nextImplementation);
            if (data.length != 0) {
                (bool ok, bytes memory returned) = nextImplementation.delegatecall(data);
                if (!ok) assembly { revert(add(returned, 32), mload(returned)) }
            }
            return;
        }
        _delegate();
    }

    receive() external payable { _delegate(); }

    function _delegate() internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            let implementation_ := sload(slot)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), implementation_, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

contract ProxyUpgradeActor {
    uint256 public successfulCalls;
    function execute(address target, bytes calldata data) external returns (bool success) {
        (success, ) = target.call(data);
        // Always write the metric slot, including a zero delta for the secure
        // rejection. The paired verifier requires a trace-derived SSTORE in
        // both scenarios rather than treating an absent write as a measured zero.
        successfulCalls = successfulCalls + (success ? 1 : 0);
    }
}
