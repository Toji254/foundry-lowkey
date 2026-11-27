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

    // Test-only forwarding hook used to verify the immutable Transparent admin
    // branch sees the ProxyAdmin contract as msg.sender.
    function callProxy(address proxy, bytes calldata data)
        external returns (bool success, bytes memory returned)
    {
        require(msg.sender == _owner, "ONLY_OWNER");
        (success, returned) = proxy.call(data);
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

    constructor(address implementation_, address admin_, address initialOwner) {
        require(implementation_.code.length > 0, "NO_IMPLEMENTATION_CODE");
        require(admin_.code.length > 0, "NO_ADMIN_CODE");
        require(initialOwner != address(0), "ZERO_INITIAL_OWNER");
        _admin = admin_;
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, implementation_)
            sstore(0, initialOwner)
        }
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

// UUID-aware UUPS pair for the mismatched proxiableUUID / post-upgrade-lockout
// campaign. These are deliberately small lab fixtures, not OZ implementations.
contract UUPSUUIDSecureImplementation is LowkeyUUPSStorage {
    address public owner;

    function upgradeTo(address nextImplementation) external {
        require(msg.sender == owner, "ONLY_OWNER");
        (bool ok, bytes memory returned) = nextImplementation.staticcall(
            abi.encodeWithSignature("proxiableUUID()")
        );
        require(
            ok && returned.length == 32 && abi.decode(returned, (bytes32)) == IMPLEMENTATION_SLOT,
            "UNSUPPORTED_PROXIABLE_UUID"
        );
        _install(nextImplementation);
    }
}

contract UUPSUUIDVulnerableImplementation is LowkeyUUPSStorage {
    address public owner;

    function upgradeTo(address nextImplementation) external {
        require(msg.sender == owner, "ONLY_OWNER");
        (bool ok, bytes memory returned) = nextImplementation.staticcall(
            abi.encodeWithSignature("proxiableUUID()")
        );
        require(ok && returned.length == 32, "MISSING_PROXIABLE_UUID");
        // Deliberate defect: a readable UUID is accepted without checking the
        // ERC-1967 implementation slot value.
        _install(nextImplementation);
    }
}

contract WrongUUIDProxyReplacement {
    function proxiableUUID() external pure returns (bytes32) {
        return keccak256("LOWKEY_WRONG_PROXIABLE_UUID");
    }

    function lowkeyProxyMarker() external pure returns (bytes32) {
        return keccak256("LOWKEY_UUPS_UUID_LOCKOUT");
    }
}

contract LowkeyUUPSLockoutProxy {
    address public owner;
    bytes32 private constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address implementation_, address initialOwner) {
        require(implementation_.code.length > 0, "NO_IMPLEMENTATION_CODE");
        require(initialOwner != address(0), "ZERO_OWNER");
        owner = initialOwner;
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { sstore(slot, implementation_) }
    }

    function implementation() external view returns (address value) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { value := sload(slot) }
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

contract UUPSLockoutActor {
    uint256 public invalidUuidUpgradeAccepted;
    uint256 public recoverySucceeded;

    function attemptInvalidUpgrade(address target, address candidate) external returns (bool success) {
        (success, ) = target.call(abi.encodeWithSignature("upgradeTo(address)", candidate));
        // Always write the metric slot, including the secure zero outcome.
        invalidUuidUpgradeAccepted += success ? 1 : 0;
    }

    function attemptRecovery(address target, address candidate) external returns (bool success) {
        (success, ) = target.call(abi.encodeWithSignature("upgradeTo(address)", candidate));
        recoverySucceeded += success ? 1 : 0;
    }
}

/// Direct implementation fixture. Its constructor locks the implementation
/// using the same terminal initialized-version state used by common
/// _disableInitializers() patterns. The isolated attack branch clears only that
/// state slot to model a constructor that omitted the lock.
contract UUPSImplementationInitializationFixture {
    uint8 public initializedVersion;
    address public owner;

    constructor() {
        initializedVersion = type(uint8).max;
    }

    function initialize(address initialOwner) external {
        require(initializedVersion == 0, "ALREADY_INITIALIZED");
        require(initialOwner != address(0), "ZERO_OWNER");
        initializedVersion = 1;
        owner = initialOwner;
    }
}

contract ImplementationInitializationActor {
    uint256 public takeoverAccepted;

    function attemptInitialize(address target, address initialOwner)
        external returns (bool success)
    {
        (success, ) = target.call(
            abi.encodeWithSignature("initialize(address)", initialOwner)
        );
        uint256 nextValue;
        assembly { nextValue := sload(takeoverAccepted.slot) }
        nextValue += success ? 1 : 0;
        assembly { sstore(takeoverAccepted.slot, nextValue) }
    }
}

